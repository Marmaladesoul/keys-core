//! keyhole's implementations of the platform *ports* that `keys-ffi`'s
//! `Engine::open` injects.
//!
//! On the Mac/iOS apps these are backed by the Keychain / Secure
//! Enclave (the db key + session key) and by `NSFilePresenter` (the file
//! watcher). keyhole is just another "platform" — so it supplies its
//! own adapters. The whole point is that they are deliberately *boring
//! and deterministic*: fixed keys, no OS prompts, fully reproducible.
//! That determinism is a feature for fuzzing (controllable inputs,
//! repeatable runs), not a shortcut.
//!
//! These adapters protect keyhole's *local `SQLCipher` mirror* only.
//! They are unrelated to the KDBX master password (which flows through
//! `ingest_from_kdbx` / `save_to_kdbx`). The mirror is persistent
//! (`<vault>.mirror/` — held-conflict state survives across
//! invocations like a real client's local store), but it only ever
//! mirrors *throwaway test vaults*, so a fixed key remains fine.

use keys_ffi::{
    VaultDbKeyProvider, VaultDbKeyProviderError, VaultFieldProtector, VaultProtectorError,
};

/// `SQLCipher` key for the test-vault mirror DB. Fixed — see module docs.
const MIRROR_DB_KEY: [u8; 32] = [0x42; 32];
/// Session key wrapping protected fields inside the mirror. Fixed.
const MIRROR_SESSION_KEY: [u8; 32] = [0x9c; 32];

/// Hands the engine a fixed 32-byte `SQLCipher` key for the local mirror.
pub struct FixedDbKey;

impl VaultDbKeyProvider for FixedDbKey {
    fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
        Ok(MIRROR_DB_KEY.to_vec())
    }
}

/// Hands the engine a fixed 32-byte field-protection session key.
pub struct FixedProtector;

impl VaultFieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
        Ok(MIRROR_SESSION_KEY.to_vec())
    }
}
