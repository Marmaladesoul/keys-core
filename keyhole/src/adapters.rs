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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

    fn delete_db_key(&self) -> Result<(), VaultDbKeyProviderError> {
        // keyhole's mirror key is a compile-time constant, not stored in
        // a keystore, so there is nothing to delete — the no-op success
        // a real provider returns once the keystore entry is gone. The
        // `purge` verb uses [`RecordingDbKey`] instead, to *observe* this
        // call; ordinary opens use this boring stub.
        Ok(())
    }
}

/// A db-key provider that records whether `delete_db_key` was invoked.
///
/// keyhole has no real keystore to inspect after a purge, so this
/// stands in: the `purge` verb passes one of these to
/// [`keys_ffi::purge_vault_local_data`], then asserts the flag flipped —
/// proving the teardown drove the key-deletion half (not just the file
/// deletion). The acquired key matches the fixed mirror key, so a caller
/// that does open the mirror still unlocks it.
pub struct RecordingDbKey {
    deleted: Arc<AtomicBool>,
}

impl RecordingDbKey {
    /// A fresh provider whose deletion flag starts unset.
    #[must_use]
    pub fn new() -> Self {
        Self {
            deleted: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A handle on the shared deletion flag, readable after `purge` to
    /// confirm `delete_db_key` fired.
    #[must_use]
    pub fn deletion_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.deleted)
    }
}

impl Default for RecordingDbKey {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultDbKeyProvider for RecordingDbKey {
    fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
        Ok(MIRROR_DB_KEY.to_vec())
    }

    fn delete_db_key(&self) -> Result<(), VaultDbKeyProviderError> {
        self.deleted.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// Hands the engine a fixed 32-byte field-protection session key.
pub struct FixedProtector;

impl VaultFieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
        Ok(MIRROR_SESSION_KEY.to_vec())
    }
}
