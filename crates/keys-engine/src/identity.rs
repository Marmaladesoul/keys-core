//! Vault identity: the one rule for "is this the same vault?".
//!
//! A vault's identity is its **root-group UUID** — minted once when the vault
//! is created and preserved verbatim across every save, sync, and re-key. Two
//! vaults are the same vault iff their root-group UUIDs match.
//!
//! Every identity comparison in the stack goes through [`is_same_vault`]: the
//! engine's reconcile guard (a mirror refuses to merge a file whose root
//! differs from its own — [`crate::EngineError::VaultIdentityMismatch`]), the
//! writers' guard on the file they are about to overwrite, and the FFI's
//! pre-relink check on a user-picked file (`keys_ffi::verify_vault_identity`).
//! Keeping the rule in one place keeps its edge case — the nil UUID — from
//! being decided differently per caller.
//!
//! A file whose root lacks a UUID (keepass-core decodes an absent `<UUID>` as
//! nil) still has an identity: [`file_identity`] gives it the one
//! [`stamped_root_uuid`] derives from the file's master seed. Every reader of
//! a vault file takes its identity from there, so the engine's ingest stamps
//! that identity into the mirror (and the next write records it in the file),
//! and every gate compares it — readers and writers agree by construction.
//! The derivation is deterministic, so every device that ingests the same
//! unstamped file mints the same identity.

use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{GroupId, Vault};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Domain separator for [`stamped_root_uuid`], so the digest can't collide
/// with any other use of the master seed.
const STAMP_DOMAIN: &[u8] = b"keys-engine/stamped-root-uuid/v1";

/// Does a vault whose root-group UUID is `found` have the identity
/// `expected`?
///
/// A nil `found` is never an identity: two files that both lack a root
/// `<UUID>` are not thereby the same vault. So a nil `found` never matches —
/// not even a nil `expected`. A vault file's identity is never nil
/// ([`file_identity`]).
#[must_use]
pub fn is_same_vault(expected: Uuid, found: Uuid) -> bool {
    !found.is_nil() && found == expected
}

/// The identity of the vault file `file`: its root-group UUID, or — when the
/// root has none — the one [`stamped_root_uuid`] derives from its master seed.
/// Never nil.
#[must_use]
pub fn file_identity(file: &Kdbx<Unlocked>) -> Uuid {
    effective_root_uuid(file.vault().root.id.0, &file.outer_header().master_seed.0)
}

/// Give `vault`, read from `file`, its [`file_identity`]. Returns whether the
/// root had to be stamped — i.e. whether `file` lacks the identity `vault`
/// now carries.
pub(crate) fn assign_file_identity(vault: &mut Vault, file: &Kdbx<Unlocked>) -> bool {
    let stamped = vault.root.id.0.is_nil();
    vault.root.id = GroupId(file_identity(file));
    stamped
}

/// The root-group UUID the engine mints for a vault file whose root has none,
/// derived from that file's outer-header master seed.
///
/// The seed is random per file and regenerated on every save, so two files
/// with distinct contents never share it, while every reader of the same
/// bytes derives the same UUID. Version-4-shaped and never nil.
#[must_use]
pub fn stamped_root_uuid(master_seed: &[u8; 32]) -> Uuid {
    let digest = Sha256::new()
        .chain_update(STAMP_DOMAIN)
        .chain_update(master_seed)
        .finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

fn effective_root_uuid(root: Uuid, master_seed: &[u8; 32]) -> Uuid {
    if root.is_nil() {
        stamped_root_uuid(master_seed)
    } else {
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_non_nil_roots_are_the_same_vault() {
        let root = Uuid::new_v4();
        assert!(is_same_vault(root, root));
    }

    #[test]
    fn different_roots_are_different_vaults() {
        assert!(!is_same_vault(Uuid::new_v4(), Uuid::new_v4()));
    }

    #[test]
    fn nil_found_never_matches_even_a_nil_expected() {
        assert!(!is_same_vault(Uuid::nil(), Uuid::nil()));
        assert!(!is_same_vault(Uuid::new_v4(), Uuid::nil()));
    }

    #[test]
    fn stamp_is_deterministic_per_seed_and_never_nil() {
        let seed = [7u8; 32];
        let stamp = stamped_root_uuid(&seed);
        assert_eq!(stamp, stamped_root_uuid(&seed));
        assert_ne!(stamp, stamped_root_uuid(&[8u8; 32]));
        assert!(!stamp.is_nil());
        assert_eq!(stamp.get_version_num(), 4);
    }

    #[test]
    fn a_root_uuid_is_the_identity_and_only_a_nil_root_is_stamped() {
        let root = Uuid::new_v4();
        let seed = [7u8; 32];
        assert_eq!(effective_root_uuid(root, &seed), root);
        assert_eq!(
            effective_root_uuid(Uuid::nil(), &seed),
            stamped_root_uuid(&seed)
        );
    }

    #[test]
    fn nil_root_files_with_different_seeds_are_different_vaults() {
        let stamped = effective_root_uuid(Uuid::nil(), &[7u8; 32]);
        assert!(is_same_vault(
            stamped,
            effective_root_uuid(Uuid::nil(), &[7u8; 32])
        ));
        assert!(!is_same_vault(
            stamped,
            effective_root_uuid(Uuid::nil(), &[8u8; 32])
        ));
    }
}
