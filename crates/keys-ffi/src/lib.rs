//! # keys-ffi
//!
//! Private FFI facade for the Keys password manager. Consumes the public
//! `keepass-core` and `keepass-merge` crates and exposes a uniffi-generated
//! API for consumption by the native Swift/SwiftUI and C#/WinUI 3
//! frontends.
//!
//! API shape is driven by Keys' UI needs and carries no stability
//! guarantee for external consumers — hence this crate remains
//! closed-source and is deliberately not published to crates.io.

mod db_key_provider;
mod dto;
mod error;
mod merge;
mod observer;
mod portable;
mod protector;
mod vault;

pub use db_key_provider::{VaultDbKeyProvider, VaultDbKeyProviderError};
pub use dto::{
    AutoType, AutoTypeAssociation, CustomField, Entry, EntryCreate, EntryPatch, EntrySummary,
    Group, GroupPatch, HistoryRecord, ProtectedField,
};
pub use error::VaultError;
pub use merge::{
    AttachmentChoiceFfi, AttachmentChoiceKindFfi, AttachmentDeltaFfi, AttachmentDeltaKindFfi,
    ConflictSideFfi, DeleteEditChoiceEntryFfi, DeleteEditChoiceFfi, DeleteEditConflictFfi,
    EntryAttachmentChoiceFfi, EntryConflictFfi, EntryFieldChoiceFfi, EntryIconChoiceFfi,
    FieldChoiceFfi, FieldDeltaFfi, FieldDeltaKindFfi, IconDeltaFfi, MergeOutcome, MergeSummary,
    ResolutionFfi,
};
pub use observer::{VaultChange, VaultObserver};
pub use portable::PortableEntry;
pub use protector::{VaultFieldProtector, VaultProtectorError};
pub use vault::Vault;

uniffi::setup_scaffolding!();

/// Smoke-test entry point exercised by the Swift harness from slice 1.
///
/// Stable through the rest of Phase 2 so the harness has a trivial
/// round-trip even after `Vault` lands.
#[uniffi::export]
#[must_use]
pub fn ping() -> String {
    "keys-ffi alive".to_owned()
}

#[cfg(test)]
mod tests {
    use super::ping;

    #[test]
    fn ping_returns_expected_string() {
        assert_eq!(ping(), "keys-ffi alive");
    }
}
