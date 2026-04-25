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
}

impl From<keepass_core::Error> for VaultError {
    fn from(err: keepass_core::Error) -> Self {
        match err {
            keepass_core::Error::Io(e) => Self::Io(e.to_string()),
            keepass_core::Error::Format(
                FormatError::BadSignature1 | FormatError::BadSignature2,
            ) => Self::Format,
            _ => Self::WrongKey,
        }
    }
}
