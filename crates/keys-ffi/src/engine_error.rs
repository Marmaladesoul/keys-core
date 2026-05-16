//! [`EngineError`] — the FFI-facing error type for the [`crate::Engine`]
//! surface.
//!
//! Mirrors the actionable variants of [`keys_engine::EngineError`]
//! one-to-one (`WrongKey`, `NotFound`, `NotEvaluable`, …) and folds the
//! rest (`Sqlite`, `Random`, `Migration`, `Reveal`, `Wrap`, …) into a
//! single `Internal(String)` catch-all. The flat-rich shape was the maintainer's
//! 2026-05-16 call: variants that the frontend can act on (retry vs.
//! prompt for a new key vs. surface a generic error toast) get their own
//! arm; everything else is opaque.
//!
//! `flat_error` keeps the wire shape simple — Swift/Kotlin sees the
//! variant plus a stringified message from `Display`. No nested
//! payloads cross the FFI; the variant discriminator IS the actionable
//! signal.

#![allow(clippy::doc_markdown)]

use crate::db_key_provider::VaultDbKeyProviderError;
use crate::protector::VaultProtectorError;

/// Errors surfaced across the FFI by every [`crate::Engine`] method.
///
/// See the module-level docs for the actionable-vs-internal split.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum EngineError {
    /// The supplied [`crate::VaultDbKeyProvider`] key does not decrypt
    /// the SQLite database. Frontends should re-prompt for keychain
    /// auth or surface a "wrong key" message — distinct from a
    /// generic backend failure.
    #[error("wrong key")]
    WrongKey,

    /// The persisted schema is at a version this binary doesn't know
    /// how to read. Frontends should surface "please update the app"
    /// rather than retrying.
    #[error("schema too new: binary supports {binary_max}, file is at {file_current}")]
    SchemaTooNew {
        /// Highest schema version this binary can read.
        binary_max: u32,
        /// Schema version currently persisted in the file.
        file_current: u32,
    },

    /// The requested entity (entry, group, smart folder, attachment,
    /// custom field, history snapshot, conflict payload, …) doesn't
    /// exist. `entity` carries the short label the engine uses
    /// internally — useful for error messages, not intended as a
    /// machine-readable taxonomy.
    #[error("not found: {entity}")]
    NotFound {
        /// Short label naming the missing entity kind.
        entity: String,
    },

    /// The supplied predicate (or the predicate persisted in a smart
    /// folder) cannot be compiled to SQL — typically because it
    /// contains an `Unknown` node written by a newer client this
    /// binary doesn't know how to evaluate. Frontends should surface
    /// "this smart folder needs a newer app".
    #[error("predicate is not evaluable by this binary")]
    NotEvaluable,

    /// A user-supplied conflict resolution didn't line up with the
    /// stashed conflict payload (unknown entry, unknown field, missing
    /// per-entry decision, `KeepBoth` on a single-sided attachment).
    /// Carries the upstream `keepass-merge` validation message.
    #[error("resolution does not match stashed conflict: {reason}")]
    ResolutionMismatch {
        /// Validation diagnostic from `keepass-merge`.
        reason: String,
    },

    /// A group move would create a cycle (the new parent is the group
    /// itself, or one of its descendants).
    #[error("group move would create a cycle")]
    CycleDetected,

    /// The [`crate::VaultDbKeyProvider`] failed to materialise the
    /// database key — e.g. Keychain auth was declined or the entry
    /// was missing. Distinct from [`Self::WrongKey`] (which is "key
    /// supplied but wrong"); this is "couldn't get a key at all".
    #[error("key provider error: {0}")]
    KeyProvider(String),

    /// The [`crate::VaultFieldProtector`] failed to materialise a
    /// session key while a reveal / wrap call needed one.
    #[error("field protector error: {0}")]
    FieldProtector(String),

    /// Catch-all for internal engine errors that aren't user-actionable.
    /// SQLite errors, migration runner failures, RNG failures, IO,
    /// projection, serialise, reveal-decode, file-watcher-init —
    /// everything that boils down to "something broke; reopen and
    /// retry" — collapses to this variant.
    #[error("internal engine error: {0}")]
    Internal(String),
}

impl From<keys_engine::EngineError> for EngineError {
    fn from(err: keys_engine::EngineError) -> Self {
        use keys_engine::EngineError as E;
        match err {
            E::WrongKey => Self::WrongKey,
            E::NotFound { entity } => Self::NotFound {
                entity: entity.to_owned(),
            },
            E::NotEvaluable => Self::NotEvaluable,
            E::ResolutionMismatch { reason } => Self::ResolutionMismatch { reason },
            E::CycleDetected => Self::CycleDetected,
            E::KeyProvider(e) => Self::KeyProvider(e.to_string()),
            E::Migration(ref _e) => {
                // Migration's `SchemaTooNew` variant could be unpacked
                // here once it carries the binary/file pair. Until then
                // it collapses to Internal — the Display message is
                // still informative.
                Self::Internal(err.to_string())
            }
            // Everything else — Sqlite, Io, Random, Ingest, Projection,
            // Reveal, Serialise, Wrap, SessionKey, FileWatcher —
            // collapses to Internal. Sealed by `#[non_exhaustive]` on
            // the engine side; the catch-all guards against future
            // variants we haven't classified.
            other => Self::Internal(other.to_string()),
        }
    }
}

impl From<VaultDbKeyProviderError> for EngineError {
    fn from(err: VaultDbKeyProviderError) -> Self {
        match err {
            VaultDbKeyProviderError::KeyUnavailable(msg) => Self::KeyProvider(msg),
        }
    }
}

impl From<VaultProtectorError> for EngineError {
    fn from(err: VaultProtectorError) -> Self {
        match err {
            VaultProtectorError::KeyUnavailable(msg) => Self::FieldProtector(msg),
        }
    }
}
