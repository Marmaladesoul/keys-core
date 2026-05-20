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
    Predicate, SearchScope, SmartFolder, Strength, StrengthBucket, TagUsageCount, VaultState,
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

/// Compute the character-class entropy and strength bucket of a password.
///
/// Pure function; no engine instance required. Used by the password
/// generator preview (where the password isn't persisted yet) and by
/// any client wanting to score an arbitrary string. For entries that
/// already exist in a vault, prefer the persisted
/// `password_strength_bucket` / `password_entropy` columns on
/// [`EngineEntrySummary`] / [`EntryFull`] — same algorithm, no
/// recomputation.
#[uniffi::export]
#[must_use]
pub fn password_strength(password: &str) -> Strength {
    keys_engine::strength(password).into()
}

/// Options for generating a pronounceable password. Mirrors
/// [`keys_engine::syllable_generator::SyllableOptions`].
#[derive(uniffi::Record, Debug, Clone, Copy)]
pub struct SyllableOptions {
    pub syllable_count: u32,
    pub capitalise_one: bool,
}

impl From<SyllableOptions> for keys_engine::syllable_generator::SyllableOptions {
    fn from(o: SyllableOptions) -> Self {
        Self {
            syllable_count: o.syllable_count,
            capitalise_one: o.capitalise_one,
        }
    }
}

/// Generate a pronounceable password from random syllables.
#[uniffi::export]
#[must_use]
pub fn syllable_generate(options: SyllableOptions) -> String {
    keys_engine::syllable_generator::generate(&options.into())
}

/// Estimate the entropy (in bits) of a pronounceable password generated
/// with the given options.
#[uniffi::export]
#[must_use]
pub fn syllable_estimate_entropy(options: SyllableOptions) -> f64 {
    keys_engine::syllable_generator::estimate_entropy(&options.into())
}

#[cfg(test)]
mod tests {
    use super::{
        StrengthBucket, SyllableOptions, eff_random_word, eff_word_at, eff_word_count,
        password_strength, ping, syllable_estimate_entropy, syllable_generate,
    };

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

    #[test]
    #[allow(clippy::float_cmp)] // the engine documents an exact 0.0 return for empty input
    fn empty_password_is_very_weak_zero_entropy() {
        let s = password_strength("");
        assert_eq!(s.entropy_bits, 0.0);
        assert_eq!(s.bucket, StrengthBucket::VeryWeak);
    }

    #[test]
    fn short_lowercase_is_weak() {
        let s = password_strength("abcdef");
        assert!(s.entropy_bits > 0.0 && s.entropy_bits < 50.0);
        assert_eq!(s.bucket, StrengthBucket::Weak);
    }

    #[test]
    fn long_mixed_is_very_strong() {
        let s = password_strength("Tr0ub4dor&3-Correct-Horse-Battery-Staple");
        assert!(s.entropy_bits >= 100.0);
        assert_eq!(s.bucket, StrengthBucket::VeryStrong);
    }

    #[test]
    fn syllable_generate_returns_non_empty() {
        let s = syllable_generate(SyllableOptions {
            syllable_count: 4,
            capitalise_one: true,
        });
        assert!(!s.is_empty());
    }

    #[test]
    fn syllable_entropy_is_positive() {
        let bits = syllable_estimate_entropy(SyllableOptions {
            syllable_count: 4,
            capitalise_one: true,
        });
        assert!(bits > 0.0);
    }
}
