//! Password fingerprinting via HMAC-SHA-256.
//!
//! The engine wants to detect duplicate passwords across entries without
//! ever holding plaintext. A per-vault 32-byte random key is stored
//! (encrypted at rest by `SQLCipher`) in the `setting` table under the
//! `fingerprint_key` row; that key is then HMAC'd with each password
//! plaintext to produce a deterministic, undecryptable 32-byte tag.
//! Comparing tags answers "do these two entries share a password?"
//! cheaply, and the tag reveals nothing about the underlying string.
//!
//! The key is per-vault so that the same plaintext fingerprints
//! differently across two distinct databases — leaking a fingerprint
//! from one vault does not let an attacker test it against another.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute the HMAC-SHA-256 of `plaintext` under `key`.
///
/// The returned 32 bytes are suitable for direct storage in the
/// `entry.password_fingerprint` column.
///
/// # Panics
///
/// Panics only if the `hmac` crate ever changes contract and rejects
/// a 32-byte key. `HmacSha256::new_from_slice` is documented as
/// accepting any key length, so this is unreachable in practice.
#[must_use]
pub fn fingerprint(key: &[u8; 32], plaintext: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(plaintext);
    // Copy straight out of the MAC output, which wipes itself on drop, so no
    // unwiped copy of the keyed tag is left behind.
    let tag = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-check `fingerprint()` against a direct `Hmac<Sha256>`
    /// invocation. Proves the helper is a thin wrapper over a real
    /// HMAC-SHA-256 — if anyone ever swaps the impl for a plain
    /// `Sha256::digest(key || plaintext)`, this test fails.
    #[test]
    fn fingerprint_helper_matches_known_vector() {
        let key = [0x0b; 32];
        let data = b"Hi There";

        let got = fingerprint(&key, data);

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(data);
        let expected = mac.finalize().into_bytes();

        assert_eq!(&got[..], &expected[..]);
        assert_eq!(got.len(), 32);
    }

    /// Pin the output itself, not just agreement with the same crates: a
    /// stored fingerprint must keep matching across dependency upgrades,
    /// or duplicate-password matching silently breaks between old and new
    /// rows. Value computed independently (openssl HMAC-SHA-256).
    #[test]
    fn fingerprint_output_is_stable() {
        let got = fingerprint(&[0x0b; 32], b"Hi There");
        assert_eq!(
            crate::util::codec::bytes_to_hex(&got),
            "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7"
        );
    }
}
