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
//! ## The verdict — why `Undecryptable` is not "different vault"
//!
//! [`verify_vault_identity`] returns [`VaultIdentityVerdict`]:
//!
//! - [`Match`](VaultIdentityVerdict::Match) — decrypts and the root-group UUID
//!   equals the expected one. The same vault: the caller may proceed.
//! - [`Mismatch`](VaultIdentityVerdict::Mismatch) — decrypts but the
//!   root-group UUID differs (or is a nil/absent identity). A **different**
//!   vault: the caller must reject. This is the only *definitive* reject.
//! - [`Undecryptable`](VaultIdentityVerdict::Undecryptable) — the supplied
//!   key material didn't open the file (a key refusal, per
//!   [`keys_engine::error::is_key_refusal`]). This is **ambiguous**, not a
//!   "different vault" verdict: it can mean a wrong file, **the genuine vault
//!   re-keyed since the caller cached its credential** (identity preserved,
//!   credential rotated), or damage that can't be told from a wrong key by
//!   design — a KDBX4 file's keyed header HMAC, or anywhere in a KDBX3 file's
//!   payload (KDBX3 proves the key only by decrypting and verifying the
//!   payload, so telling its damage from a wrong key would be a padding
//!   oracle). A caller must therefore NOT treat `Undecryptable` as a
//!   definitive reject — it should re-derive / re-prompt for the *current*
//!   credential and retry before giving up, so a re-keyed vault recovered on a
//!   device holding the stale credential is not falsely rejected.
//! - [`Unreadable`](VaultIdentityVerdict::Unreadable) — a KDBX file that
//!   couldn't be read for a reason other than the key. Its identity is
//!   unknown, so it is not `Mismatch`; and it is not a key problem, so
//!   re-prompting won't help. The caller rejects it and points the user at
//!   another copy. Three kinds of damage reach it:
//!   - a KDBX4 file damaged past its keyed header HMAC (truncated, a corrupt
//!     payload block, contents that won't decompress or parse), reached only
//!     once the key is proven, so never in place of a refusal;
//!   - a header damaged in a way detected without the key: a field that
//!     doesn't parse, an unsupported version, KDF parameters that don't
//!     decode, or a KDBX4 header failing its SHA-256 hash. These checks are
//!     unkeyed, so reporting them under any credential reveals nothing about
//!     the key;
//!   - a KDBX3 header field that parses but holds the wrong value (its
//!     compression flags flipped, its inner random stream id changed). The
//!     KDBX3 outer header is unauthenticated, so this is noticed only after
//!     the key is proven: `Unreadable` under the right key, `Undecryptable`
//!     under a wrong one.
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

use std::path::Path;

use keepass_core::kdbx::Kdbx;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::error::VaultError;
use crate::keyfile::composite_from_factors;

/// The outcome of comparing a picked KDBX file against an expected vault
/// identity. See the module-level docs for why `Undecryptable` is distinct
/// from `Mismatch` (the re-key case), and `Unreadable` from both.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultIdentityVerdict {
    /// Decrypts and the root-group UUID equals the expected one — the same
    /// vault. Safe to proceed.
    Match,
    /// Decrypts but the root-group UUID differs (or is a nil/absent identity)
    /// — a different vault. The definitive reject.
    Mismatch,
    /// The supplied key material didn't open it — ambiguous (wrong file, the
    /// genuine vault re-keyed since this credential was cached, or damage that
    /// can't be told from a wrong key: a KDBX4 file's keyed header HMAC, or
    /// anywhere in a KDBX3 file's payload). NOT a "different vault" verdict;
    /// re-derive / re-prompt and retry before rejecting.
    Undecryptable,
    /// A KDBX file that couldn't be read for a reason other than the key: a
    /// KDBX4 file damaged past its keyed header HMAC, header damage detected
    /// without the key (under any credential), or a KDBX3 header field that
    /// parses but holds the wrong value (noticed once the key is proven). Its
    /// identity is unknown and re-prompting won't help: reject it and ask for
    /// another copy.
    Unreadable,
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
/// - [`VaultError::KdfApprovalRequired`] if the file's KDF settings go past
///   this process's ceiling and aren't `approved_kdf` (see
///   [`crate::KdfSettings`]) — refused from the header, before deriving. A
///   caller re-linking a vault it knows can pass that vault's recorded
///   settings (`Engine::recorded_kdf`) as the approval.
///
/// A wrong password or malformed keyfile does NOT error: it is reported as
/// [`VaultIdentityVerdict::Undecryptable`], because "won't open under this
/// credential" is a verdict the caller acts on (re-derive), not an exceptional
/// failure. Likewise damage the module docs list as
/// [`VaultIdentityVerdict::Unreadable`] is a verdict the caller acts on by
/// asking for another copy.
#[uniffi::export(default(approved_kdf = None))]
pub fn verify_vault_identity(
    path: String,
    password: String,
    keyfile: Option<Vec<u8>>,
    expected_root_uuid: String,
    approved_kdf: Option<crate::KdfSettings>,
) -> Result<VaultIdentityVerdict, VaultError> {
    let approved = crate::kdf::approved_cost(approved_kdf)
        .map_err(|e| VaultError::Unexpected(e.to_string()))?;
    let secret = SecretString::from(password);
    // Same composite construction as create / open / re-key, so a
    // keyfile-keyed vault verifies under exactly the key material that opens
    // it. A malformed keyfile is key material that doesn't open the file.
    let Ok(composite) =
        composite_from_factors(secret.expose_secret().as_bytes(), keyfile.as_deref())
    else {
        return Ok(VaultIdentityVerdict::Undecryptable);
    };

    let read = match Kdbx::open(Path::new(&path)).and_then(Kdbx::read_header) {
        Ok(read) => read,
        Err(e) => return verdict_for_unopened(e),
    };
    // KDF parameters that don't decode are header damage found without the
    // key, like a header field that doesn't parse.
    let Ok(kdf_params) = read.header().decode_kdf_params() else {
        return Ok(VaultIdentityVerdict::Unreadable);
    };
    // No mirror to hold the file's KDF settings to: the ceiling, or the
    // caller's approval.
    crate::kdf::check_unrecorded_cost(&keys_engine::KdfCost::of(&kdf_params), approved.as_ref())?;
    // No field protector: we read only the group tree's root id, never a
    // protected field, and the unlocked vault is dropped before we return.
    match read.unlock_with_protector(&composite, crate::protector::bridge(None)) {
        Ok(kdbx) => Ok(classify(
            keys_engine::identity::file_identity(&kdbx),
            &expected_root_uuid,
        )),
        Err(e) => verdict_for_unopened(e),
    }
}

/// The verdict on a picked file `keepass-core` failed to open, read the header
/// of, or unlock.
///
/// Only a key refusal ([`keys_engine::error::is_key_refusal`]) is
/// [`VaultIdentityVerdict::Undecryptable`]. I/O, no KDBX magic and a
/// field-protector failure are errors the caller can't resolve by
/// re-deriving. Every other failure is [`VaultIdentityVerdict::Unreadable`].
///
/// `keepass_core::Error` is `#[non_exhaustive]`: a keepass-core pin bump must
/// re-audit any new variant against the collapse contract below (only a key
/// refusal may stand for a wrong key) and give it an explicit arm. A variant
/// without one trips a `debug_assert!`, so CI catches the gap on the first
/// test that reaches it.
fn verdict_for_unopened(err: keepass_core::Error) -> Result<VaultIdentityVerdict, VaultError> {
    use keepass_core::Error;
    use keepass_core::format::FormatError;
    match err {
        e if keys_engine::error::is_key_refusal(&e) => Ok(VaultIdentityVerdict::Undecryptable),
        // Not about the file's contents, so errors as `VaultError` names them.
        // A protector failure is unreachable while the unlock passes no field
        // protector; it stays an error because a protector failing is not
        // damage to the file.
        e @ (Error::Io(_)
        | Error::Format(FormatError::BadSignature1 | FormatError::BadSignature2)
        | Error::Protector(_)) => Err(e.into()),
        // A deliberate classification, not a fallback. The only failure that
        // can stand for a wrong key is the refusal matched above: a KDBX4
        // file's key is proven by its keyed header HMAC, a KDBX3 file's by
        // decrypting and verifying its payload, and `keepass-core` reports
        // either failing as that refusal. Every other failure comes from an
        // unkeyed check on the header, or from a file after its key was
        // proven, so it is damage to the file.
        Error::Crypto(_) | Error::Format(_) | Error::Xml(_) | Error::Model(_) => {
            Ok(VaultIdentityVerdict::Unreadable)
        }
        // A variant newer than this mapping. Release builds still read it as
        // `Unreadable`: `keepass-core` reports a wrong key as the refusal
        // above, so a new variant is not one, and reading it as `Undecryptable`
        // would send the caller round a re-prompt loop.
        other => {
            debug_assert!(
                false,
                "unmapped keepass_core::Error variant in verify_vault_identity: {other:?}"
            );
            Ok(VaultIdentityVerdict::Unreadable)
        }
    }
}

/// Compare a decrypted picked file's identity against the expected identity
/// string, under the engine's single identity rule
/// ([`keys_engine::identity::is_same_vault`]) — the same rule the reconcile
/// guard applies.
///
/// A nil/all-zeros `picked` is never an identity, so it can never `Match` —
/// even against a nil `expected` (a file's identity is never nil: see
/// [`keys_engine::identity::file_identity`]). A malformed `expected` likewise
/// never matches.
fn classify(picked: Uuid, expected_root_uuid: &str) -> VaultIdentityVerdict {
    match Uuid::parse_str(expected_root_uuid) {
        Ok(expected) if keys_engine::identity::is_same_vault(expected, picked) => {
            VaultIdentityVerdict::Match
        }
        _ => VaultIdentityVerdict::Mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(s: &str) -> Uuid {
        Uuid::parse_str(s).expect("valid uuid")
    }

    // These pin every currently-known `keepass_core::Error` shape to its
    // verdict, so a change to the classification shows up as a test change.
    mod verdict_for_unopened {
        use super::super::*;
        use keepass_core::Error;
        use keepass_core::crypto::CryptoError;
        use keepass_core::format::FormatError;
        use keepass_core::model::ModelError;
        use keepass_core::protector::ProtectorError;
        use keepass_core::xml::XmlError;

        fn verdict(err: impl Into<Error>) -> Result<VaultIdentityVerdict, VaultError> {
            verdict_for_unopened(err.into())
        }

        fn assert_unreadable(err: impl Into<Error>) {
            assert!(matches!(verdict(err), Ok(VaultIdentityVerdict::Unreadable)));
        }

        #[test]
        fn key_refusal_is_undecryptable() {
            assert!(matches!(
                verdict(CryptoError::Decrypt),
                Ok(VaultIdentityVerdict::Undecryptable)
            ));
        }

        #[test]
        fn io_is_an_io_error() {
            assert!(matches!(
                verdict(std::io::Error::other("disk")),
                Err(VaultError::Io(_))
            ));
        }

        #[test]
        fn bad_magic_is_a_format_error() {
            assert!(matches!(
                verdict(FormatError::BadSignature1),
                Err(VaultError::Format)
            ));
            assert!(matches!(
                verdict(FormatError::BadSignature2),
                Err(VaultError::Format)
            ));
        }

        #[test]
        fn protector_failure_is_a_protector_error() {
            assert!(matches!(
                verdict(ProtectorError::KeyUnavailable("locked".into())),
                Err(VaultError::Protector(_))
            ));
        }

        #[test]
        fn kdf_failure_is_unreadable() {
            assert_unreadable(CryptoError::Kdf);
        }

        #[test]
        fn payload_block_hmac_mismatch_is_unreadable() {
            assert_unreadable(CryptoError::HmacMismatch { index: 0 });
        }

        #[test]
        fn unsupported_version_is_unreadable() {
            assert_unreadable(FormatError::UnsupportedVersion { major: 9, minor: 0 });
        }

        #[test]
        fn header_hash_mismatch_is_unreadable() {
            assert_unreadable(FormatError::HeaderHashMismatch);
        }

        #[test]
        fn truncation_is_unreadable() {
            assert_unreadable(FormatError::Truncated { needed: 64, got: 1 });
        }

        #[test]
        fn malformed_header_is_unreadable() {
            assert_unreadable(FormatError::MalformedHeader("payload failed to decompress"));
        }

        #[test]
        fn malformed_xml_is_unreadable() {
            assert_unreadable(XmlError::Malformed("mismatched tag".into()));
        }

        #[test]
        fn model_error_is_unreadable() {
            assert_unreadable(ModelError::CannotDeleteRoot);
        }
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
