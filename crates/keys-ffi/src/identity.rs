//! Vault-identity seam: decide whether a user-picked KDBX file is the **same
//! vault** as one the caller already knows, without trusting its path.
//!
//! A vault's identity is its **root-group UUID** — minted once when the vault
//! is created and preserved verbatim across every save, sync, **and re-key**.
//! (Re-key rotates the master credential but leaves the inner XML, and thus
//! the root-group UUID, untouched — see `Engine::rekey_to_kdbx` /
//! `Vault::rekey`.) Two files are the same vault iff their root-group UUIDs
//! match.
//!
//! This matters for any "re-anchor a vault to a file the user picked"
//! (recovery / relocate) flow. Such a flow is path-based and trusting by
//! nature, so without an identity check it can silently re-point a vault's
//! stable identity (and its local store) at a *different* vault's file, then
//! ingest the wrong contents on the next unlock. The caller holds the
//! *expected* identity already (from its open engine, or its SQLCipher
//! sidecar — neither needs the master password) and passes it in;
//! [`verify_vault_identity`] reads the *picked* file's identity and returns
//! the verdict.
//!
//! ## The three-way verdict — why `Undecryptable` is not "different vault"
//!
//! [`verify_vault_identity`] returns [`VaultIdentityVerdict`]:
//!
//! - [`Match`](VaultIdentityVerdict::Match) — decrypts and the root-group UUID
//!   equals the expected one. The same vault: the caller may proceed.
//! - [`Mismatch`](VaultIdentityVerdict::Mismatch) — decrypts but the
//!   root-group UUID differs (or is a nil/absent identity). A **different**
//!   vault: the caller must reject. This is the only *definitive* reject.
//! - [`Undecryptable`](VaultIdentityVerdict::Undecryptable) — the file would
//!   not open under the supplied key material. This is **ambiguous**, not a
//!   "different vault" verdict: it can mean a wrong file, a corrupt file, **or
//!   the genuine vault re-keyed since the caller cached its credential**
//!   (identity preserved, credential rotated). A caller must therefore NOT
//!   treat `Undecryptable` as a definitive reject — it should re-derive /
//!   re-prompt for the *current* credential and retry before giving up, so a
//!   re-keyed vault recovered on a device holding the stale credential is not
//!   falsely rejected.
//!
//! Centralising the verdict here (rather than leaving each client to compare a
//! raw UUID and classify a decrypt error) is what keeps the re-key nuance from
//! being re-derived — and fumbled — per client.
//!
//! This is a pure read of the raw KDBX (decrypt + parse the inner XML), with
//! no `Engine` / SQLCipher-mirror involvement — it opens the file directly
//! through `keepass-core`, off the `Engine` path entirely.

// The uniffi-exported function takes owned `String` / `Vec<u8>` even where it
// only borrows — the natural FFI shape, matching the rest of this crate's
// surface (see `vault/mod.rs`). Product/tech names (KDBX, SQLCipher) read
// naturally in the prose above without backticks, as in `keyfile.rs`.
#![allow(clippy::needless_pass_by_value, clippy::doc_markdown)]

use keepass_core::kdbx::Kdbx;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::error::VaultError;
use crate::keyfile::composite_from_factors;

/// The outcome of comparing a picked KDBX file against an expected vault
/// identity. See the module-level docs for why `Undecryptable` is distinct
/// from `Mismatch` (the re-key case).
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultIdentityVerdict {
    /// Decrypts and the root-group UUID equals the expected one — the same
    /// vault. Safe to proceed.
    Match,
    /// Decrypts but the root-group UUID differs (or is a nil/absent identity)
    /// — a different vault. The definitive reject.
    Mismatch,
    /// Would not open under the supplied key material — ambiguous (wrong file,
    /// corrupt, or the genuine vault re-keyed since this credential was
    /// cached). NOT a "different vault" verdict; re-derive / re-prompt and
    /// retry before rejecting.
    Undecryptable,
}

/// Decide whether the KDBX file at `path` is the **same vault** as the one
/// identified by `expected_root_uuid`, decrypting it with `password` plus an
/// optional `keyfile`.
///
/// `expected_root_uuid` is the caller's known root-group UUID for the vault
/// being recovered (e.g. from `Engine::group_tree`'s parentless node, read
/// without the master password). `keyfile` is the raw keyfile *file content*
/// (32-byte binary, 64-char hex, or an XML `.keyx`), or `None` for a
/// password-only vault.
///
/// The file is opened, the root UUID read, the comparison made, and the
/// unlocked vault dropped immediately — no handle is retained and no mirror is
/// created or touched.
///
/// See the module-level docs for the verdict semantics and the consumer
/// contract — in particular that [`VaultIdentityVerdict::Undecryptable`] is
/// ambiguous (covers a genuine re-keyed vault) and must not be treated as a
/// definitive "different vault" reject.
///
/// # Errors
///
/// - [`VaultError::Io`] if `path` cannot be read (missing, permission).
/// - [`VaultError::Format`] if the file is not a KDBX file at all (bad magic).
///
/// A wrong password / malformed keyfile / corruption past the magic does NOT
/// error: it is reported as [`VaultIdentityVerdict::Undecryptable`], because
/// "won't open under this credential" is a verdict the caller acts on (re-
/// derive), not an exceptional failure.
#[uniffi::export]
pub fn verify_vault_identity(
    path: String,
    password: String,
    keyfile: Option<Vec<u8>>,
    expected_root_uuid: String,
) -> Result<VaultIdentityVerdict, VaultError> {
    match read_root_uuid(&path, &password, keyfile.as_deref()) {
        Ok(picked) => Ok(classify(picked, &expected_root_uuid)),
        // "Won't open under this credential" is a verdict, not an error — it
        // covers a genuine re-keyed vault as well as a wrong/corrupt file.
        Err(VaultError::WrongKey) => Ok(VaultIdentityVerdict::Undecryptable),
        // Missing file / not-a-KDBX are genuine read failures the caller can't
        // resolve by re-deriving a credential.
        Err(e) => Err(e),
    }
}

/// Compare a decrypted picked root UUID against the expected identity string.
///
/// A nil/all-zeros `picked` is never an identity (keepass-core defaults an
/// absent `<UUID>` element to [`Uuid::nil`]), so it can never `Match` — even
/// against a nil `expected`. A malformed `expected` likewise never matches.
fn classify(picked: Uuid, expected_root_uuid: &str) -> VaultIdentityVerdict {
    if picked.is_nil() {
        return VaultIdentityVerdict::Mismatch;
    }
    match Uuid::parse_str(expected_root_uuid) {
        Ok(expected) if expected == picked => VaultIdentityVerdict::Match,
        _ => VaultIdentityVerdict::Mismatch,
    }
}

/// Read the root-group UUID of the KDBX at `path`, decrypting with `password`
/// plus an optional `keyfile`. The internal building block behind
/// [`verify_vault_identity`]; not exported, so the verdict is the only seam a
/// consumer can act on.
fn read_root_uuid(path: &str, password: &str, keyfile: Option<&[u8]>) -> Result<Uuid, VaultError> {
    let secret = SecretString::from(password.to_owned());
    // Same composite construction as create / open / re-key, so a
    // keyfile-keyed vault verifies under exactly the key material that opens
    // it. A malformed keyfile fails closed (collapsed to `WrongKey`, which the
    // caller surfaces as `Undecryptable`).
    let composite = composite_from_factors(secret.expose_secret().as_bytes(), keyfile)
        .map_err(|_| VaultError::WrongKey)?;

    // No field protector: we read only the group tree's root id, never a
    // protected field, and the unlocked vault is dropped before we return.
    let kdbx = Kdbx::open(std::path::Path::new(path))?
        .read_header()?
        .unlock_with_protector(&composite, crate::protector::bridge(None))?;

    Ok(kdbx.vault().root.id.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(s: &str) -> Uuid {
        Uuid::parse_str(s).expect("valid uuid")
    }

    #[test]
    fn equal_non_nil_uuids_match() {
        let id = uuid("11111111-1111-1111-1111-111111111111");
        assert_eq!(
            classify(id, "11111111-1111-1111-1111-111111111111"),
            VaultIdentityVerdict::Match
        );
    }

    #[test]
    fn different_uuids_mismatch() {
        let picked = uuid("11111111-1111-1111-1111-111111111111");
        assert_eq!(
            classify(picked, "22222222-2222-2222-2222-222222222222"),
            VaultIdentityVerdict::Mismatch
        );
    }

    #[test]
    fn nil_picked_never_matches_even_a_nil_expected() {
        // A nil/absent root UUID is not a usable identity — defence in depth
        // against two files that both decrypt and both carry a nil root.
        assert_eq!(
            classify(Uuid::nil(), "00000000-0000-0000-0000-000000000000"),
            VaultIdentityVerdict::Mismatch
        );
    }

    #[test]
    fn malformed_expected_never_matches() {
        let picked = uuid("11111111-1111-1111-1111-111111111111");
        assert_eq!(
            classify(picked, "not-a-uuid"),
            VaultIdentityVerdict::Mismatch
        );
    }
}
