//! [`VaultError`] — the single error type surfaced across the FFI for the
//! whole `Vault` surface.
//!
//! ## Error-collapse discipline
//!
//! `keepass-core` deliberately collapses "wrong key" and "corrupt
//! ciphertext" into a single failure mode at the crypto layer (see
//! `Kdbx::<HeaderRead>::unlock` in `keepass-core` for the rationale —
//! avoiding an oracle on the key from the error variant alone). This crate
//! preserves and extends that collapse: only the bad-magic case (the file
//! isn't a KDBX file at all) surfaces as [`VaultError::Format`]; everything
//! else past the magic — wrong password, corrupt HMAC, truncation,
//! malformed inner XML — surfaces as [`VaultError::WrongKey`].
//!
//! `WrongKey`'s `Display` message is a fixed string regardless of which
//! `keepass-core` variant fed in. Do not `format!` the underlying error
//! into it.

use keepass_core::format::FormatError;
use keepass_core::model::ModelError;

/// Errors returned across the FFI by every `Vault` method.
///
/// `flat_error` means uniffi serialises this as a single string (from
/// [`std::fmt::Display`]) on the wire — Swift sees an enum variant plus a
/// stringified message.
#[derive(thiserror::Error, Debug, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum VaultError {
    /// Filesystem I/O failed (path missing, permission denied, read error).
    #[error("io: {0}")]
    Io(String),

    /// The file isn't a KDBX file at all (bad magic).
    #[error("not a kdbx file")]
    Format,

    /// Wrong password, corrupt vault, or any other failure past the magic.
    /// The message is fixed by design — see crate-level error-collapse
    /// docs.
    #[error("wrong key or corrupt vault")]
    WrongKey,

    /// A method was called on a [`crate::Vault`] that has already been
    /// locked. Lifecycle: a locked vault is permanently poisoned —
    /// frontends reconstruct a new `Vault` to unlock again.
    #[error("vault is locked")]
    Locked,

    /// A `uuid` argument did not match any entry or group in the vault.
    /// Unit variant by design — same collapse posture as
    /// [`Self::WrongKey`]; the caller already knows the uuid they
    /// passed in.
    #[error("entry or group not found")]
    NotFound,

    /// Asked to reveal or clear a protected field by a name that
    /// doesn't match any protected slot on the entry. Distinct from
    /// [`Self::NotFound`] (entry-level miss). Same fixed-Display
    /// posture, no payload.
    #[error("protected field not found")]
    FieldNotFound,

    /// A history index passed to `restore_entry_from_history` /
    /// `delete_history_at` was outside `0..entry.history.len()`.
    /// Distinct from [`Self::NotFound`] — the entry exists; the
    /// index doesn't. Same fixed-Display posture, no payload.
    #[error("history index out of range")]
    IndexOutOfRange,

    /// A merge resolution was inconsistent with the outcome it was
    /// built against — e.g. the outcome contains an entry conflict
    /// the resolution doesn't cover, the resolution names a field
    /// the conflict's `field_deltas` doesn't list, or a UUID inside
    /// the resolution doesn't parse. The string carries the upstream
    /// `keepass_merge::MergeError` Display (or a UUID-parse hint) so
    /// the binding side can surface a useful diagnostic without
    /// importing merge-crate types.
    ///
    /// Distinct from [`Self::NotFound`] — these are
    /// resolution-validation failures, not entry-lookup misses.
    #[error("merge resolution invalid: {0}")]
    Merge(String),

    /// A [`crate::VaultFieldProtector`] wrap or unwrap call failed.
    /// Surfaced from [`crate::Vault::new`] (wrap at unlock), from
    /// reveal-side accessors (`reveal_field`,
    /// `reveal_history_field`), and from save (unwrap before
    /// re-encrypt). The string carries the upstream protector's
    /// supplied detail.
    ///
    /// Distinct from [`Self::WrongKey`] so frontends can distinguish
    /// "Secure Enclave unavailable" from "wrong password" without
    /// stringly-matching the message.
    #[error("field protector failed: {0}")]
    Protector(String),

    /// A new variant of an upstream `#[non_exhaustive]` error enum
    /// (`keepass_core::model::ModelError`, `keepass_merge::MergeError`)
    /// reached the FFI facade without an explicit mapping in this
    /// crate. Debug builds (and therefore CI) `debug_assert!` on this
    /// path so the gap is caught the first time a test exercises the
    /// new variant; release builds degrade safely to surfacing this
    /// variant rather than aborting across the FFI boundary (which
    /// would be UB on the Swift consumer side).
    ///
    /// Treat this variant as "Keys binary is older than the database /
    /// merge crate it's reading" — the binding should prompt the user
    /// to update.
    #[error("unexpected internal error: {0}")]
    Unexpected(String),
}

/// Map a [`ModelError`] from any mutation call onto [`VaultError`].
///
/// Every currently-known variant collapses to a specific [`VaultError`]
/// variant. `ModelError` is `#[non_exhaustive]` upstream, so a wildcard
/// arm is unavoidable — but rather than panic across the FFI boundary
/// (UB on the Swift side), the wildcard surfaces
/// [`VaultError::Unexpected`] and trips a `debug_assert!` so CI catches
/// the mapping gap on the first test that exercises the new variant.
/// That preserves the "forced code review" intent of the original
/// `panic!` (per the #R8 carry-forward) while removing the UB.
pub(crate) fn model_err_to_vault_err(err: ModelError) -> VaultError {
    match err {
        ModelError::EntryNotFound(_)
        | ModelError::GroupNotFound(_)
        | ModelError::CircularMove { .. }
        | ModelError::DuplicateUuid(_)
        | ModelError::CannotDeleteRoot => VaultError::NotFound,
        ModelError::HistoryIndexOutOfRange { .. } => VaultError::IndexOutOfRange,
        ModelError::Protector(e) => VaultError::Protector(e.to_string()),
        other => {
            debug_assert!(
                false,
                "unmapped keepass_core::model::ModelError variant in keys-ffi facade: {other:?}"
            );
            VaultError::Unexpected(format!("unmapped ModelError: {other}"))
        }
    }
}

impl From<keepass_core::Error> for VaultError {
    fn from(err: keepass_core::Error) -> Self {
        match err {
            keepass_core::Error::Io(e) => Self::Io(e.to_string()),
            keepass_core::Error::Format(
                FormatError::BadSignature1 | FormatError::BadSignature2,
            ) => Self::Format,
            keepass_core::Error::Protector(e) => Self::Protector(e.to_string()),
            _ => Self::WrongKey,
        }
    }
}

#[cfg(test)]
mod tests {
    //! These tests pin every currently-known `ModelError` variant to its
    //! intended `VaultError` collapse. When `keepass-core` adds a new
    //! `ModelError` variant, the wildcard arm in `model_err_to_vault_err`
    //! degrades to `VaultError::Unexpected` (rather than panicking across
    //! the FFI boundary) — but the `debug_assert!` inside that arm makes
    //! `cargo test` panic in debug builds, which is how CI catches the
    //! mapping gap before a release ships.
    //!
    //! Note: we *can't* directly construct an "unknown future variant" to
    //! exercise the fallthrough path — the upstream enum is
    //! `#[non_exhaustive]` but every existing variant is mapped. The
    //! presence of these per-variant pinning tests is what makes the
    //! `debug_assert!` actionable: a new upstream variant landing without
    //! a corresponding test failure here means a CI gap, not a code gap.
    use super::*;
    use keepass_core::model::{EntryId, GroupId};
    use uuid::Uuid;

    #[test]
    fn entry_not_found_collapses_to_not_found() {
        let v = model_err_to_vault_err(ModelError::EntryNotFound(EntryId(Uuid::nil())));
        assert!(matches!(v, VaultError::NotFound));
    }

    #[test]
    fn group_not_found_collapses_to_not_found() {
        let v = model_err_to_vault_err(ModelError::GroupNotFound(GroupId(Uuid::nil())));
        assert!(matches!(v, VaultError::NotFound));
    }

    #[test]
    fn circular_move_collapses_to_not_found() {
        let v = model_err_to_vault_err(ModelError::CircularMove {
            moving: GroupId(Uuid::nil()),
            new_parent: GroupId(Uuid::nil()),
        });
        assert!(matches!(v, VaultError::NotFound));
    }

    #[test]
    fn duplicate_uuid_collapses_to_not_found() {
        let v = model_err_to_vault_err(ModelError::DuplicateUuid(Uuid::nil()));
        assert!(matches!(v, VaultError::NotFound));
    }

    #[test]
    fn cannot_delete_root_collapses_to_not_found() {
        // Regression guard: prior to the audit fix this variant fell
        // through to the panic arm, which would UB across the FFI.
        let v = model_err_to_vault_err(ModelError::CannotDeleteRoot);
        assert!(matches!(v, VaultError::NotFound));
    }

    #[test]
    fn history_index_out_of_range_collapses_to_index_out_of_range() {
        let v = model_err_to_vault_err(ModelError::HistoryIndexOutOfRange {
            id: EntryId(Uuid::nil()),
            index: 5,
            len: 2,
        });
        assert!(matches!(v, VaultError::IndexOutOfRange));
    }

    #[test]
    fn unexpected_variant_renders_actionable_display() {
        // Spot-check the Display surface so binding-side logs stay
        // useful; the actual fallthrough is exercised in debug builds
        // by the `debug_assert!` and in release by structural
        // construction here.
        let v = VaultError::Unexpected("unmapped ModelError: SomethingNew".into());
        assert_eq!(
            v.to_string(),
            "unexpected internal error: unmapped ModelError: SomethingNew",
        );
    }
}
