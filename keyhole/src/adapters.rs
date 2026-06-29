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
//!
//! ## Forcing a stale-key state (sidecar self-heal tests)
//!
//! Both keys default to compile-time constants, but each can be
//! overridden per-process via an env var holding 32 bytes of hex:
//! `KEYHOLE_DB_KEY` (the `SQLCipher` mirror key) and `KEYHOLE_FIELD_KEY`
//! (the field-protection session key). This is the lever a self-heal
//! scenario pulls to reproduce the failure a keystore reset causes on a
//! real client: seed the mirror under the default key in one process,
//! then reopen in a second process with a *different* key. The mirror
//! file survives but its key is "gone" — opening it now fails the same
//! way a real client's does when the keystore was wiped, so the
//! self-heal (discard the sidecar, re-ingest from the `.kdbx`) is what
//! must rescue it. A malformed override is a hard error, not a silent
//! fall back to the default — a scenario that fat-fingers the key should
//! see it, not a misleadingly-passing run.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use keys_ffi::{
    VaultDbKeyProvider, VaultDbKeyProviderError, VaultFieldProtector, VaultProtectorError,
};

/// `SQLCipher` key for the test-vault mirror DB. Fixed — see module docs.
const MIRROR_DB_KEY: [u8; 32] = [0x42; 32];
/// Session key wrapping protected fields inside the mirror. Fixed.
const MIRROR_SESSION_KEY: [u8; 32] = [0x9c; 32];

/// Env var overriding [`MIRROR_DB_KEY`] (32 bytes of hex). See module docs.
const DB_KEY_ENV: &str = "KEYHOLE_DB_KEY";
/// Env var overriding [`MIRROR_SESSION_KEY`] (32 bytes of hex). See module docs.
const FIELD_KEY_ENV: &str = "KEYHOLE_FIELD_KEY";

/// Resolve an optional 32-byte key override from `env_var` (32 bytes of
/// hex). The caller applies its own default when there is no override.
///
/// `Ok(None)` ⇒ the var is unset (use the default); `Ok(Some(bytes))` ⇒
/// a valid override; `Err(msg)` ⇒ the var is set but isn't exactly 32
/// bytes of hex. The error is surfaced (never swallowed) so a scenario
/// can't pass on a typo'd key.
fn key_override(env_var: &str) -> Result<Option<[u8; 32]>, String> {
    let Ok(hex) = std::env::var(env_var) else {
        return Ok(None);
    };
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!(
            "{env_var} must be 64 hex chars (32 bytes); got {} chars",
            hex.len()
        ));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        // Both nibbles are 0..=15, so `(hi << 4) | lo` fits a u8 with no
        // truncation — and working in u8 keeps the cast-lint quiet.
        bytes[i] = (hex_nibble(chunk[0], env_var)? << 4) | hex_nibble(chunk[1], env_var)?;
    }
    Ok(Some(bytes))
}

/// Decode one ASCII hex digit to its 0..=15 nibble value.
fn hex_nibble(c: u8, env_var: &str) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("{env_var}: non-hex char {:?}", c as char)),
    }
}

/// Hands the engine a 32-byte `SQLCipher` key for the local mirror —
/// [`MIRROR_DB_KEY`] by default, or the [`DB_KEY_ENV`] override.
pub struct FixedDbKey;

impl VaultDbKeyProvider for FixedDbKey {
    fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
        match key_override(DB_KEY_ENV) {
            Ok(Some(bytes)) => Ok(bytes.to_vec()),
            Ok(None) => Ok(MIRROR_DB_KEY.to_vec()),
            Err(msg) => Err(VaultDbKeyProviderError::KeyUnavailable(msg)),
        }
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

/// Hands the engine a 32-byte field-protection session key —
/// [`MIRROR_SESSION_KEY`] by default, or the [`FIELD_KEY_ENV`] override.
///
/// Reopening with a *different* field key is how a scenario forces the
/// session-key-unwrap arm of the self-heal: the mirror's protected
/// blobs were sealed under the seeding key, so a read under the new key
/// fails AES-GCM (a stale-session-key signal — the headless analogue of
/// a real client's Secure-Enclave session key being rotated out).
pub struct FixedProtector;

impl VaultFieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
        match key_override(FIELD_KEY_ENV) {
            Ok(Some(bytes)) => Ok(bytes.to_vec()),
            Ok(None) => Ok(MIRROR_SESSION_KEY.to_vec()),
            Err(msg) => Err(VaultProtectorError::KeyUnavailable(msg)),
        }
    }
}
