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

use uuid::Uuid;

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
}
