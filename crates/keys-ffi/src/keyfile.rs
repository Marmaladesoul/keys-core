//! Keyfile seam for the FFI: the single place that turns key *factors*
//! (a password plus an optional keyfile) into a [`CompositeKey`], plus the
//! keyfile mint primitive.
//!
//! The engine stays storage-agnostic. It mints 32 bytes of keyfile material
//! and consumes raw keyfile *bytes*, but never decides where the keyfile is
//! stored — that choice (OS keychain on the GUI clients, a sibling file for
//! the headless keyhole driver, removable media) belongs to each consumer.
//! See `keepass_core::keyfile_hash` for the keyfile-format rules and the
//! standard interoperable composite this builds on.

// Product names (KeePass, KeePassXC, KeyFile) read naturally in prose here, as
// they do across this crate's docs (see `engine_error.rs`) — they are not code.
#![allow(clippy::doc_markdown)]

use keepass_core::{CompositeKey, KeyFileError};

use crate::engine_error::EngineError;

/// Build the KDBX composite key from a password and an optional keyfile.
///
/// With no keyfile this is the password-only composite. With one, it reduces
/// the raw keyfile *file contents* (32-byte binary, 64-char hex, or an XML
/// `.keyx`) to a 32-byte hash via [`keepass_core::keyfile_hash`] and forms the
/// standard interoperable KDBX composite
/// `SHA-256(SHA-256(password) || keyfile_hash)`. The keyfile-format rules live
/// in `keepass-core`; this is the single seam where Keys turns key factors
/// into a [`CompositeKey`].
///
/// # Errors
///
/// Returns [`KeyFileError`] if `keyfile` is present but cannot be reduced to a
/// 32-byte hash (malformed `.keyx`, failed v2 integrity checksum, unsupported
/// version, …) — a fail-closed signal the caller maps onto its own error type.
pub(crate) fn composite_from_factors(
    password: &[u8],
    keyfile: Option<&[u8]>,
) -> Result<CompositeKey, KeyFileError> {
    match keyfile {
        None => Ok(CompositeKey::from_password(password)),
        Some(bytes) => {
            let hash = keepass_core::keyfile_hash(bytes)?;
            Ok(CompositeKey::from_password_and_keyfile_hash(
                password, &hash,
            ))
        }
    }
}

/// [`composite_from_factors`] mapped onto [`EngineError`] for the `Engine`
/// open / save / rekey / reconcile paths. A malformed keyfile fails closed
/// here rather than deriving a wrong composite and surfacing a confusing
/// "wrong key" further down.
///
/// # Errors
///
/// [`EngineError::Internal`] if the keyfile cannot be reduced to 32 bytes.
pub(crate) fn composite_for_engine(
    password: &[u8],
    keyfile: Option<&[u8]>,
) -> Result<CompositeKey, EngineError> {
    composite_from_factors(password, keyfile)
        .map_err(|e| EngineError::Internal(format!("keyfile: {e}")))
}

/// Mint a fresh per-vault keyfile and return its file content: a KeePass
/// KeyFile v2 (`.keyx`) document carrying 32 bytes of OS-CSPRNG entropy plus a
/// 4-byte integrity checksum — the self-describing format KeePassXC /
/// KeePass 2 generate and prefer, so a Keys-minted keyfile also opens those
/// clients.
///
/// The returned bytes *are* the keyfile. The caller stores them (OS keychain
/// on the GUI clients, a file for keyhole) and supplies them back at open /
/// save / rekey time; the engine keeps no copy.
///
/// # Errors
///
/// Returns [`EngineError::Internal`] if the OS CSPRNG fails (vanishingly rare).
#[uniffi::export]
pub fn generate_keyfile() -> Result<Vec<u8>, EngineError> {
    let doc = keepass_core::generate_keyfile_keyx_v2()
        .map_err(|e| EngineError::Internal(format!("keyfile mint: {e}")))?;
    Ok(doc.as_bytes().to_vec())
}
