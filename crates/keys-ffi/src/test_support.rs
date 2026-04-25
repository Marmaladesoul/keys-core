//! Feature-gated test affordances.
//!
//! Compiled only when the crate's `test_helpers` feature is on. Slice 7
//! lands the production [`crate::Vault::save`] / `save_to_bytes` surface
//! and **this whole module is deleted** at the same time — so don't
//! grow it. One method, one purpose.

// Same mutex-poisoning panic as every other Vault method — see vault.rs.
#![allow(clippy::missing_panics_doc)]

use crate::Vault;
use crate::error::VaultError;

#[uniffi::export]
impl Vault {
    /// Serialise the in-memory vault back to encrypted KDBX bytes.
    ///
    /// Slice-4-only test affordance for "mutate, save, reopen, assert"
    /// round-trips. Mirrors `keepass_core::kdbx::Kdbx::save_to_bytes`
    /// 1:1 — see that crate for the formatting/canonicalisation
    /// guarantees. Slice 7 replaces this with the production
    /// `save_to_bytes` (and `save`) and the integration tests rename.
    ///
    /// # Errors
    ///
    /// [`VaultError::Locked`] if the vault has been locked.
    /// [`VaultError::WrongKey`] for any failure during re-encryption
    /// (these are crypto-level errors during the canonical re-emit;
    /// the same collapse posture as `Vault::new` applies).
    pub fn save_to_bytes_for_tests(&self) -> Result<Vec<u8>, VaultError> {
        let guard = self.inner.lock().expect("Vault mutex poisoned");
        let kdbx = guard.as_ref().ok_or(VaultError::Locked)?;
        kdbx.save_to_bytes().map_err(VaultError::from)
    }
}
