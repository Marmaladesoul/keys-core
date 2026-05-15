//! [`KeyProvider`] — pluggable callback trait for sourcing the
//! `SQLCipher` database key used to encrypt the on-disk `SQLite` mirror.
//!
//! Parallel in shape to `keepass_core::protector::FieldProtector`,
//! distinct in role:
//!
//! - `FieldProtector` produces an AES-256 **session key** that wraps
//!   individual protected fields *in memory*.
//! - `KeyProvider` produces the 32-byte raw key that `SQLCipher` uses
//!   to encrypt the *on-disk* database file.
//!
//! Different keys, different lifetimes, same discipline: the engine
//! asks the frontend for the key each time it opens the database,
//! holds the bytes only as long as needed to issue `PRAGMA key`, then
//! drops the [`DbKey`] wrapper to zeroise the buffer.
//!
//! The frontend is expected to source the raw key from the platform
//! secret store (macOS / iOS Keychain; Android Keystore; Windows
//! DPAPI) — *not* derive it from a master password. That keeps the
//! authentication ceremony (biometric / passcode) on the platform
//! side and the engine code path key-derivation-free.

use std::fmt::Debug;

use zeroize::Zeroizing;

/// A `SQLCipher` database key — 32 raw bytes, zeroised on drop.
///
/// Constructed by [`KeyProvider`] implementations and consumed by the
/// engine's open path. Conceptually parallel to
/// `keepass_core::protector::SessionKey` but distinct because the
/// `SQLCipher` key has a different lifecycle and role from the field
/// session key — colocating them under one name would obscure which
/// is which at the call site.
#[derive(Clone)]
pub struct DbKey(Zeroizing<[u8; 32]>);

impl DbKey {
    /// Wrap a raw 32-byte key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the underlying key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Debug for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DbKey(<redacted>)")
    }
}

/// A pluggable provider of the 32-byte `SQLCipher` database key.
///
/// Implementations must be `Send + Sync` so the provider can be shared
/// across threads alongside the engine handle.
///
/// The implementation is expected to do whatever the platform requires
/// to materialise the key (e.g. read it out of the Keychain via a
/// single IPC) and return the raw bytes. The engine does not cache
/// the returned [`DbKey`] — every `Engine::open` triggers a fresh
/// `acquire_db_key` call.
pub trait KeyProvider: Send + Sync + Debug {
    /// Return the 32-byte `SQLCipher` database key.
    ///
    /// Called once per engine open. The implementation is responsible
    /// for fetching its backing key material on each call; this crate
    /// does not cache the returned [`DbKey`].
    ///
    /// # Errors
    ///
    /// Returns [`KeyProviderError::KeyUnavailable`] if the underlying
    /// key material can't be produced (e.g. Keychain auth failure or
    /// missing entry).
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError>;
}

/// Errors surfaced by a [`KeyProvider`] implementation.
///
/// Mirrors `keepass_core::protector::ProtectorError` in shape — a
/// single `KeyUnavailable(String)` variant is enough for the open
/// path, where any failure to produce the key collapses to "can't
/// unlock the database". Richer diagnostics live in the string
/// payload.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyProviderError {
    /// The implementation could not produce the database key.
    #[error("db key provider key unavailable: {0}")]
    KeyUnavailable(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixedKey([u8; 32]);

    impl KeyProvider for FixedKey {
        fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
            Ok(DbKey::from_bytes(self.0))
        }
    }

    #[derive(Debug)]
    struct FailingKey(String);

    impl KeyProvider for FailingKey {
        fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
            Err(KeyProviderError::KeyUnavailable(self.0.clone()))
        }
    }

    #[test]
    fn db_key_round_trips_bytes() {
        let raw = [7u8; 32];
        let key = DbKey::from_bytes(raw);
        assert_eq!(key.as_bytes(), &raw);
    }

    #[test]
    fn db_key_debug_redacts() {
        let key = DbKey::from_bytes([0u8; 32]);
        assert_eq!(format!("{key:?}"), "DbKey(<redacted>)");
    }

    #[test]
    fn provider_returns_key() {
        let provider = FixedKey([3u8; 32]);
        let key = provider.acquire_db_key().expect("key");
        assert_eq!(key.as_bytes(), &[3u8; 32]);
    }

    #[test]
    fn provider_propagates_error() {
        let provider = FailingKey("keychain locked".into());
        let err = provider.acquire_db_key().expect_err("must error");
        assert_eq!(
            err,
            KeyProviderError::KeyUnavailable("keychain locked".into()),
        );
        assert_eq!(
            err.to_string(),
            "db key provider key unavailable: keychain locked",
        );
    }
}
