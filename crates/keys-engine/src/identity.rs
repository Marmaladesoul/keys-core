//! Vault identity: the one rule for "is this the same vault?".
//!
//! A vault's identity is its **root-group UUID** — minted once when the vault
//! is created and preserved verbatim across every save, sync, and re-key. Two
//! vaults are the same vault iff their root-group UUIDs match.
//!
//! Every identity comparison in the stack goes through [`is_same_vault`]: the
//! engine's reconcile guard (a mirror refuses to merge a file whose root
//! differs from its own — [`crate::EngineError::VaultIdentityMismatch`]) and
//! the FFI's pre-relink check on a user-picked file
//! (`keys_ffi::verify_vault_identity`). Keeping the rule in one place keeps
//! its edge case — the nil UUID — from being decided differently per caller.
//!
//! A file whose root lacks a UUID (keepass-core decodes an absent `<UUID>` as
//! nil) has no identity to compare, so the engine gives it one when it first
//! ingests the file: [`stamped_root_uuid`], derived from the file's master
//! seed. The derivation is deterministic, so every device that ingests the
//! same unstamped file mints the same identity, and it is what lets the first
//! write prove — via [`may_overwrite`] — that the nil-root file it is about to
//! replace is the very file the identity was minted from.

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Domain separator for [`stamped_root_uuid`], so the digest can't collide
/// with any other use of the master seed.
const STAMP_DOMAIN: &[u8] = b"keys-engine/stamped-root-uuid/v1";

/// Does a vault whose root-group UUID is `found` have the identity
/// `expected`?
///
/// A nil `found` is never an identity: keepass-core defaults an absent root
/// `<UUID>` element to [`Uuid::nil`], and two files that both lack one are not
/// thereby the same vault. So a nil `found` never matches — not even a nil
/// `expected`.
#[must_use]
pub fn is_same_vault(expected: Uuid, found: Uuid) -> bool {
    !found.is_nil() && found == expected
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

/// May a mirror whose root is `expected` overwrite the file whose root is
/// `found` and whose master seed is `file_master_seed`?
///
/// Yes for the same vault ([`is_same_vault`]). Also yes for a nil-root file
/// whose seed stamps exactly `expected`: that is the unstamped file this
/// mirror minted its identity from, still unchanged (any rewrite draws a new
/// seed), and the write is what gives it that identity. Any other nil-root
/// file is a different vault.
#[must_use]
pub fn may_overwrite(expected: Uuid, found: Uuid, file_master_seed: &[u8; 32]) -> bool {
    is_same_vault(expected, found)
        || (found.is_nil() && expected == stamped_root_uuid(file_master_seed))
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
    fn a_nil_root_file_may_be_overwritten_only_by_the_mirror_stamped_from_it() {
        let seed = [7u8; 32];
        let stamp = stamped_root_uuid(&seed);
        assert!(may_overwrite(stamp, Uuid::nil(), &seed));
        // Another nil-root file (different seed) is a different vault.
        assert!(!may_overwrite(stamp, Uuid::nil(), &[8u8; 32]));
        // A mirror that wasn't stamped from this file.
        assert!(!may_overwrite(Uuid::new_v4(), Uuid::nil(), &seed));
        assert!(!may_overwrite(Uuid::nil(), Uuid::nil(), &seed));
    }

    #[test]
    fn may_overwrite_follows_the_identity_rule_for_identified_files() {
        let root = Uuid::new_v4();
        let seed = [7u8; 32];
        assert!(may_overwrite(root, root, &seed));
        assert!(!may_overwrite(root, Uuid::new_v4(), &seed));
        // The stamp only ever vouches for a nil-root file.
        assert!(!may_overwrite(
            stamped_root_uuid(&seed),
            Uuid::new_v4(),
            &seed
        ));
    }
}
