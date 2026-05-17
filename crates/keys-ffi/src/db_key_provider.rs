//! [`VaultDbKeyProvider`] — the FFI-facing key-provider trait that
//! foreign code (Swift on the iOS/macOS Keychain; C# on DPAPI;
//! Kotlin on the Android Keystore) implements to source the 32-byte
//! `SQLCipher` database key.
//!
//! Mirrors `keys_engine::KeyProvider`. The two traits exist in
//! parallel because uniffi's `with_foreign` trait export requires the
//! trait to live in this crate — we can't re-export the upstream
//! trait as a uniffi trait. Adaptation happens via
//! [`BridgeDbKeyProvider`] below.
//!
//! The `Db` qualifier disambiguates this from [`VaultFieldProtector`]
//! at the call site: when an engine open eventually takes both, the
//! types name themselves.
//!
//! Per the migration's security posture, the raw key bytes are
//! sourced from the platform secret store — *not* derived from a
//! master password. The frontend does whatever platform IPC it needs
//! and hands the 32 raw bytes across the FFI. The engine issues a
//! single `PRAGMA key` and drops the bytes promptly.

use std::fmt::Debug;
use std::sync::Arc;

use keys_engine::{DbKey, KeyProvider, KeyProviderError as EngineKeyProviderError};

/// Foreign-implemented database-key provider for `SQLCipher` unlock.
///
/// Pass an `Arc<dyn VaultDbKeyProvider>` to the engine open call site
/// (lands with task 1.3) to source the `SQLCipher` key. Implementations
/// are expected to perform whatever platform-specific work is needed
/// (e.g. Keychain read with biometric prompt) on each call; this FFI
/// does not cache the returned bytes.
///
/// Implementations must be `Send + Sync`.
#[uniffi::export(with_foreign)]
pub trait VaultDbKeyProvider: Send + Sync {
    /// Return the 32-byte `SQLCipher` database key.
    ///
    /// Called once per engine open. The returned `Vec<u8>` MUST be
    /// exactly 32 bytes long. Any other length surfaces as
    /// [`VaultDbKeyProviderError::KeyUnavailable`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultDbKeyProviderError::KeyUnavailable`] if the
    /// underlying key material can't be produced (e.g. Keychain auth
    /// failure or missing entry).
    fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError>;
}

/// FFI-facing parallel of `keys_engine::KeyProviderError`.
///
/// Deliberately NOT `#[uniffi(flat_error)]`: this enum is the error
/// type for a `with_foreign` trait method, so uniffi must be able to
/// **lift** it (foreign-throws-to-Rust). `flat_error` enums can only
/// be lowered (Rust-throws-to-foreign); attempting to lift one panics
/// at runtime with "Can't lift flat errors". The Swift side still sees
/// a `KeyUnavailable(message:)` case with the stringified detail —
/// only the wire representation differs.
#[derive(thiserror::Error, Debug, uniffi::Error)]
#[non_exhaustive]
pub enum VaultDbKeyProviderError {
    /// The implementation could not produce the database key.
    #[error("db key provider key unavailable: {0}")]
    KeyUnavailable(String),
}

impl From<VaultDbKeyProviderError> for EngineKeyProviderError {
    fn from(err: VaultDbKeyProviderError) -> Self {
        match err {
            VaultDbKeyProviderError::KeyUnavailable(msg) => Self::KeyUnavailable(msg),
        }
    }
}

/// Adapter that lets a foreign-implemented [`VaultDbKeyProvider`]
/// satisfy keys-engine's [`KeyProvider`] trait.
///
/// `Debug` is required by the upstream trait but cannot be required
/// on a uniffi `with_foreign` trait, so we implement it manually with
/// a fixed string — it's only used for error context.
pub(crate) struct BridgeDbKeyProvider {
    inner: Arc<dyn VaultDbKeyProvider>,
}

impl BridgeDbKeyProvider {
    #[allow(dead_code)] // wired up at the open call site in task 1.3
    pub(crate) fn new(inner: Arc<dyn VaultDbKeyProvider>) -> Self {
        Self { inner }
    }
}

impl Debug for BridgeDbKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BridgeDbKeyProvider(<foreign>)")
    }
}

impl KeyProvider for BridgeDbKeyProvider {
    fn acquire_db_key(&self) -> Result<DbKey, EngineKeyProviderError> {
        let raw = self
            .inner
            .acquire_db_key()
            .map_err(EngineKeyProviderError::from)?;
        let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            EngineKeyProviderError::KeyUnavailable(format!(
                "expected 32-byte key, got {} bytes",
                raw.len()
            ))
        })?;
        Ok(DbKey::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedKey(Vec<u8>);

    impl VaultDbKeyProvider for FixedKey {
        fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
            Ok(self.0.clone())
        }
    }

    struct FailingKey(String);

    impl VaultDbKeyProvider for FailingKey {
        fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
            Err(VaultDbKeyProviderError::KeyUnavailable(self.0.clone()))
        }
    }

    #[test]
    fn bridge_round_trips_a_valid_key() {
        let raw = vec![9u8; 32];
        let bridge = BridgeDbKeyProvider::new(Arc::new(FixedKey(raw.clone())));
        let key = bridge.acquire_db_key().expect("32-byte key accepted");
        assert_eq!(key.as_bytes().as_slice(), raw.as_slice());
    }

    fn unwrap_unavailable(err: EngineKeyProviderError) -> String {
        match err {
            EngineKeyProviderError::KeyUnavailable(msg) => msg,
            other => panic!("expected KeyUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn bridge_rejects_short_key() {
        let bridge = BridgeDbKeyProvider::new(Arc::new(FixedKey(vec![1u8; 16])));
        let err = bridge.acquire_db_key().expect_err("must reject");
        let msg = unwrap_unavailable(err);
        assert!(
            msg.contains("expected 32-byte key, got 16 bytes"),
            "unexpected message: {msg}",
        );
    }

    #[test]
    fn bridge_rejects_long_key() {
        let bridge = BridgeDbKeyProvider::new(Arc::new(FixedKey(vec![1u8; 64])));
        let err = bridge.acquire_db_key().expect_err("must reject");
        let msg = unwrap_unavailable(err);
        assert!(
            msg.contains("expected 32-byte key, got 64 bytes"),
            "unexpected message: {msg}",
        );
    }

    #[test]
    fn bridge_propagates_foreign_error() {
        let bridge = BridgeDbKeyProvider::new(Arc::new(FailingKey("keychain locked".into())));
        let err = bridge.acquire_db_key().expect_err("must propagate");
        let msg = unwrap_unavailable(err);
        assert_eq!(msg, "keychain locked");
    }

    #[test]
    fn ffi_error_maps_to_engine_error() {
        let ffi = VaultDbKeyProviderError::KeyUnavailable("boom".into());
        let engine: EngineKeyProviderError = ffi.into();
        assert_eq!(
            engine,
            EngineKeyProviderError::KeyUnavailable("boom".into()),
        );
    }
}
