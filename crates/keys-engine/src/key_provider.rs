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
    /// ## Durability contract (the purge counterpart)
    ///
    /// This method MUST NOT silently mint a fresh key to satisfy an open
    /// of an existing mirror: a missing keystore entry MUST surface as
    /// [`KeyProviderError::KeyUnavailable`]. Provisioning a key is the
    /// exclusive job of the client's deliberate vault-*add* path, which
    /// writes the keystore entry **before** the first open. That split is
    /// what makes
    /// [`Engine::purge_local_data`](crate::Engine::purge_local_data)
    /// durable: after a purge the entry is intentionally gone, and it
    /// stays gone until a deliberate re-add provisions a new one — *open
    /// never provisions*. A mint-on-miss `acquire_db_key` would hand out
    /// a usable key on the next open and reopen the crypto-shred window.
    ///
    /// # Errors
    ///
    /// Returns [`KeyProviderError::KeyUnavailable`] if the underlying key
    /// material can't be produced (e.g. Keychain auth failure, or a
    /// missing entry — which, per the contract above, is surfaced, never
    /// auto-minted).
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError>;

    /// Destroy the database key this provider sources, so the encrypted
    /// `SQLite` mirror it unlocked can never be decrypted again.
    ///
    /// Called by [`Engine::purge_local_data`](crate::Engine::purge_local_data)
    /// as the key-deletion half of vault teardown: the engine deletes the
    /// on-disk mirror sidecar files (it owns the layout) and asks the
    /// provider to remove the key from wherever the platform keeps it
    /// (Keychain / Keystore / DPAPI). The engine owns the *sequence*;
    /// the provider owns the *mechanism*.
    ///
    /// ## Contract (load-bearing — purge is crypto-shredding)
    ///
    /// The mirror file is *unlinked*, not byte-scrubbed, so the
    /// confidentiality of a purged vault rests **entirely** on this key
    /// becoming unrecoverable. The seam cannot verify the platform
    /// honoured it, so it is a contract:
    ///
    /// - The key item MUST be destroyed such that it cannot resurface,
    ///   which means it MUST have been created **non-synchronizable**
    ///   (never propagated to a cloud keychain) and **backup-excluded** —
    ///   this call reaches only the local store, so a copy synced or
    ///   captured in a device backup survives and, paired with the
    ///   (unlinked but physically lingering) ciphertext, defeats the
    ///   crypto-shred.
    /// - It MUST be idempotent: deleting an already-absent key is
    ///   **success**, so a re-run of a partially-failed purge converges.
    ///
    /// ## Default — fails closed
    ///
    /// The default implementation **returns an error**, not `Ok`. A
    /// provider that reaches the purge sequence without a real
    /// key-destruction mechanism must not be able to report a successful
    /// purge while leaving the key live — the worst direction, since the
    /// unlinked ciphertext lingers in free blocks and the key is the
    /// recoverable remnant. So an unoverridden `delete_db_key` makes
    /// [`Engine::purge_local_data`](crate::Engine::purge_local_data)
    /// return [`KeyProviderError::KeyUnavailable`] rather than silently
    /// succeed. Acquire-only providers (the engine's read-only test
    /// doubles) inherit this default but never call purge, so they never
    /// hit it. The shipping contract is additionally enforced at the FFI
    /// `VaultDbKeyProvider` seam, where this method is *required*, so
    /// every platform implementor wires a real keystore delete.
    ///
    /// # Errors
    ///
    /// Returns [`KeyProviderError::KeyUnavailable`] if the platform
    /// refuses the deletion (e.g. keystore locked), or — for the
    /// fail-closed default — if the provider does not implement it.
    fn delete_db_key(&self) -> Result<(), KeyProviderError> {
        Err(KeyProviderError::KeyUnavailable(
            "delete_db_key not implemented for this KeyProvider".into(),
        ))
    }
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

    #[test]
    fn delete_db_key_default_fails_closed() {
        // A provider that only implements `acquire_db_key` inherits the
        // trait's fail-closed `delete_db_key`: it must REFUSE, not claim
        // success, so a purge can't report done while the key lives on.
        let provider = FixedKey([1u8; 32]);
        match provider
            .delete_db_key()
            .expect_err("default delete must fail closed")
        {
            KeyProviderError::KeyUnavailable(msg) => assert!(
                msg.contains("not implemented"),
                "default error should name the unimplemented method: {msg}",
            ),
        }
    }

    #[derive(Debug)]
    struct RecordingKey {
        // `KeyProvider: Send + Sync`, so interior mutability must be
        // thread-safe — an atomic, not a `Cell`.
        deleted: std::sync::atomic::AtomicBool,
    }

    impl KeyProvider for RecordingKey {
        fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
            Ok(DbKey::from_bytes([2u8; 32]))
        }
        fn delete_db_key(&self) -> Result<(), KeyProviderError> {
            self.deleted
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn delete_db_key_override_is_invoked() {
        use std::sync::atomic::Ordering;
        let provider = RecordingKey {
            deleted: std::sync::atomic::AtomicBool::new(false),
        };
        assert!(!provider.deleted.load(Ordering::SeqCst));
        provider.delete_db_key().expect("override delete succeeds");
        assert!(
            provider.deleted.load(Ordering::SeqCst),
            "override must record the deletion",
        );
    }
}
