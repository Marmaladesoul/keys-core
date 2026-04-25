//! Opaque carrier for cross-vault entry copy.
//!
//! `keepass_core::model::PortableEntry` is `#[non_exhaustive]` with `pub(crate)`
//! fields and no serde derive — there's no way to render it as a Record
//! across the FFI. This module wraps it as a uniffi `Object` so frontends
//! pass an opaque handle from `export_entry` to `import_entry` without
//! ever inspecting the contents (and couldn't, even if they wanted to).
//!
//! ## Single-use semantics
//!
//! The carrier is **consumed by `import_entry`**. Calling `import_entry`
//! a second time on the same handle returns [`crate::VaultError::NotFound`]
//! — the inner `Mutex<Option<…>>` is `None` after the first take. This
//! is enforced at the facade because `keepass_core::Kdbx::import_entry`
//! takes ownership by value and we can't clone the carrier (no `Clone`
//! impl on the public type).

use std::sync::Mutex;

use crate::error::VaultError;

/// Opaque carrier for a single entry plus all its history, attachments,
/// and referenced custom icons. Created by [`crate::Vault::export_entry`];
/// passed to [`crate::Vault::import_entry`] **exactly once**.
#[derive(uniffi::Object)]
#[non_exhaustive]
pub struct PortableEntry {
    pub(crate) inner: Mutex<Option<keepass_core::model::PortableEntry>>,
}

// `keepass_core::PortableEntry`'s `Debug` impl already redacts secrets;
// we surface that via a thin wrapper so `expect_err` and panic messages
// don't fail to compile in callers' tests.
impl std::fmt::Debug for PortableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.inner.lock().expect("PortableEntry mutex poisoned");
        f.debug_struct("PortableEntry")
            .field("consumed", &guard.is_none())
            .finish()
    }
}

impl PortableEntry {
    /// Wrap a `keepass-core` portable entry for FFI transit.
    pub(crate) fn new(portable: keepass_core::model::PortableEntry) -> Self {
        Self {
            inner: Mutex::new(Some(portable)),
        }
    }

    /// Take ownership of the inner `PortableEntry`. Returns
    /// [`VaultError::NotFound`] if it has already been imported.
    pub(crate) fn take(&self) -> Result<keepass_core::model::PortableEntry, VaultError> {
        self.inner
            .lock()
            .expect("PortableEntry mutex poisoned")
            .take()
            .ok_or(VaultError::NotFound)
    }
}
