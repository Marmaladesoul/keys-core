//! Opaque carrier for engine-side cross-database entry moves
//! (Phase 6.17-F).
//!
//! [`keys_engine::PortableEntry`] holds revealed protected-field
//! plaintext in [`SecretString`](secrecy::SecretString)s and isn't
//! `Serialize`able — wire-rendering it as a uniffi `Record` would
//! expose secrets across the FFI for no good reason. This module
//! wraps it as a uniffi `Object` so frontends pass an opaque handle
//! from [`crate::Engine::export_entry`] to
//! [`crate::Engine::import_entry`] without ever inspecting the
//! contents (and couldn't, even if they wanted to).
//!
//! ## Single-use semantics
//!
//! The carrier is **consumed by `import_entry`**. Calling
//! `import_entry` a second time on the same handle returns
//! [`crate::EngineError::Internal`] with a "carrier already consumed"
//! message — the inner `Mutex<Option<…>>` is `None` after the first
//! take. The flow is `source.exportEntry(uuid)` →
//! `target.importEntry(carrier, group)` → `source.deleteEntry(uuid)`,
//! exactly once.

use std::sync::Mutex;

use crate::engine_error::EngineError;

/// Opaque carrier for a single entry's content (every field, every
/// protected slot revealed in process, every attachment's bytes, and —
/// when the source has a custom icon — the icon's PNG bytes so the
/// target can rehome it). Created by
/// [`crate::Engine::export_entry`]; passed to
/// [`crate::Engine::import_entry`] **exactly once**.
///
/// The single portable-entry carrier: it round-trips an entry (history,
/// attachments, referenced custom icons) between vaults over the
/// SQLite-engine flows.
#[derive(uniffi::Object)]
pub struct EnginePortableEntry {
    pub(crate) inner: Mutex<Option<keys_engine::PortableEntry>>,
}

// `keys_engine::PortableEntry`'s `Debug` impl reveals tag names + field
// counts but not protected plaintext (the wrapped `SecretString`s
// redact on Debug). Wrap to keep the same redaction discipline on the
// FFI side and avoid leaking that we hold one.
impl std::fmt::Debug for EnginePortableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self
            .inner
            .lock()
            .expect("EnginePortableEntry mutex poisoned");
        f.debug_struct("EnginePortableEntry")
            .field("consumed", &guard.is_none())
            .finish()
    }
}

impl EnginePortableEntry {
    /// Wrap a `keys-engine` portable entry for FFI transit.
    pub(crate) fn new(portable: keys_engine::PortableEntry) -> Self {
        Self {
            inner: Mutex::new(Some(portable)),
        }
    }

    /// Take ownership of the inner `PortableEntry`. Returns
    /// [`EngineError::Internal`] with a sentinel message if it's
    /// already been imported.
    pub(crate) fn take(&self) -> Result<keys_engine::PortableEntry, EngineError> {
        self.inner
            .lock()
            .expect("EnginePortableEntry mutex poisoned")
            .take()
            .ok_or_else(|| EngineError::Internal("portable entry already consumed".to_owned()))
    }
}
