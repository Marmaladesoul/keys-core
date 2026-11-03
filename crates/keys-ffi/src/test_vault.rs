//! Marking a vault *file* as a test vault (see [`keys_engine::test_vault`]).
//!
//! A mirror's kind never changes in place — sync, save and re-key all refuse
//! a test vault vs ordinary-vault mismatch — so a vault's kind is set on its
//! file, before the vault is (re-)added to a client. Fixture tooling: keyhole
//! mints test vaults with it.

// uniffi exports take owned arguments across the FFI boundary.
#![allow(clippy::needless_pass_by_value)]

use secrecy::{ExposeSecret, SecretString};

use crate::engine_error::EngineError;
use crate::error::VaultError;
use crate::keyfile::composite_from_factors;
use crate::vault_create::vault_err_to_engine_err;

/// Mark the KDBX at `kdbx_path` as a test vault (`marked`), or remove the
/// marker, rewriting the file atomically under the same key factors.
/// Everything else in the vault is left as it was. `temp_dir` routes the
/// atomic write's tempfile as in `create_vault` (same volume as the vault).
///
/// The file must not be bound to a live mirror: that mirror will refuse the
/// changed file ([`EngineError::TestVaultMarkerMismatch`]) until it is
/// rebuilt from the file.
///
/// The file is derived only within this process's ceiling or at exactly
/// `approved_kdf` (see [`crate::KdfSettings`]).
///
/// # Errors
///
/// The vault errors `create_vault` reports — a wrong password or malformed
/// keyfile, IO, format — mapped onto [`EngineError`], and
/// [`EngineError::KdfApprovalRequired`] from the header, before deriving.
#[uniffi::export(async_runtime = "tokio", default(approved_kdf = None))]
pub async fn mark_test_vault_file(
    kdbx_path: String,
    password: String,
    keyfile: Option<Vec<u8>>,
    marked: bool,
    temp_dir: Option<String>,
    approved_kdf: Option<crate::KdfSettings>,
) -> Result<(), EngineError> {
    let approved = crate::kdf::approved_cost(approved_kdf)?;
    tokio::task::spawn_blocking(move || {
        rewrite_marker(
            &kdbx_path,
            password,
            keyfile.as_deref(),
            marked,
            temp_dir.as_deref(),
            approved.as_ref(),
        )
        .map_err(vault_err_to_engine_err)
    })
    .await
    .map_err(|e| EngineError::Internal(format!("join: {e}")))?
}

fn rewrite_marker(
    kdbx_path: &str,
    password: String,
    keyfile: Option<&[u8]>,
    marked: bool,
    temp_dir: Option<&str>,
    approved: Option<&keys_engine::KdfCost>,
) -> Result<(), VaultError> {
    let secret = SecretString::from(password);
    let composite = composite_from_factors(secret.expose_secret().as_bytes(), keyfile)
        .map_err(|_| VaultError::WrongKey)?;
    let path = std::path::Path::new(kdbx_path);
    // No field protector: the vault is decoded only to be re-encoded, and is
    // dropped before we return.
    let read = keepass_core::kdbx::Kdbx::open(path)?.read_header()?;
    crate::kdf::check_unrecorded_file(&read, approved)?;
    let mut kdbx = read.unlock(&composite)?;
    let mut vault = kdbx.vault().clone();
    keys_engine::test_vault::set_marked(&mut vault, marked);
    kdbx.replace_vault(vault);
    let bytes = kdbx.save_to_bytes()?;
    crate::vault_create::write_atomically(path, &bytes, temp_dir.map(std::path::Path::new))
}
