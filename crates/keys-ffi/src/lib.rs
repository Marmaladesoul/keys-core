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
mod engine;
mod engine_error;
mod engine_file_watcher;
mod engine_observer;
mod engine_portable;
mod engine_types;
mod error;
mod merge;
mod observer;
mod portable;
mod protector;
mod totp;
mod vault;

pub use db_key_provider::{VaultDbKeyProvider, VaultDbKeyProviderError};
pub use dto::{
    AutoType, AutoTypeAssociation, CustomField, Entry, EntryCreate, EntryPatch, EntrySummary,
    Group, GroupPatch, HistoryRecord, ProtectedField,
};
pub use engine::Engine;
pub use engine_error::EngineError;
pub use engine_file_watcher::{FileWatcherEvent, VaultFileWatcher, VaultFileWatcherObserver};
pub use engine_observer::{
    ChangeEvent, EntryDeletion, EntryMoveInfo, GroupDeletion, GroupMoveInfo,
    VaultDataChangeObserver,
};
pub use engine_portable::EnginePortableEntry;
pub use engine_types::{
    AttachmentRef as EngineAttachmentRef, ConflictPayloadFfi,
    CustomFieldRef as EngineCustomFieldRef, EngineEntrySummary, EntryFull,
    EntryUpdate as EngineEntryUpdate, GroupNode, GroupUpdate as EngineGroupUpdate, HistoricEntry,
    IconRef, MergeResult, MergeStats, NewCustomField, NewEntryFields, NewGroupFields, Page,
    Predicate, SearchScope, SmartFolder, StrengthBucket, TagUsageCount, VaultState,
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
pub use totp::{
    TotpAlgorithm, TotpParams, totp_base32_decode, totp_generate_code, totp_parse_uri,
    totp_progress, totp_seconds_remaining,
};
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

/// Number of words in the EFF Large Diceware word list. Always 7,776.
#[uniffi::export]
#[must_use]
#[allow(clippy::missing_panics_doc)] // statically-sized list, fits in u32 by construction
pub fn eff_word_count() -> u32 {
    // The list is statically 7,776 words — fits comfortably in u32.
    u32::try_from(keys_engine::eff_wordlist::word_count()).expect("EFF word list size fits in u32")
}

/// Indexed lookup into the EFF Large Diceware word list. Returns `None`
/// if `index` is out of range.
#[uniffi::export]
#[must_use]
pub fn eff_word_at(index: u32) -> Option<String> {
    keys_engine::eff_wordlist::word_at(index as usize).map(str::to_owned)
}

/// A uniformly random word from the EFF Large Diceware word list, drawn
/// from the OS CSPRNG.
#[uniffi::export]
#[must_use]
pub fn eff_random_word() -> String {
    keys_engine::eff_wordlist::random_word().to_owned()
}

#[cfg(test)]
mod tests {
    use super::{eff_random_word, eff_word_at, eff_word_count, ping};

    #[test]
    fn ping_returns_expected_string() {
        assert_eq!(ping(), "keys-ffi alive");
    }

    #[test]
    fn eff_word_count_is_7776() {
        assert_eq!(eff_word_count(), 7776);
    }

    #[test]
    fn eff_word_at_bounds() {
        assert_eq!(eff_word_at(0).as_deref(), Some("abacus"));
        assert_eq!(eff_word_at(7775).as_deref(), Some("zoom"));
        assert_eq!(eff_word_at(7776), None);
    }

    #[test]
    fn eff_random_word_is_non_empty() {
        assert!(!eff_random_word().is_empty());
    }
}
