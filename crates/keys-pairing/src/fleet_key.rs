//! The fleet key: one random symmetric key per account fleet document, held
//! by every device of the account, that seals every value in that document
//! and names its entries.
//!
//! Anyone holding the document's id, its write ticket or a copy of a
//! device's document store sees only sealed values under opaque entry keys.
//! The key travels in the pairing bundle and is stored readable after the
//! device's first unlock, like the device's sync keys: a locked device still
//! reads the fleet document to know which authors its vault documents bind.
//!
//! **Entry keys.** A record's entry key is `HMAC-SHA-256(K, lv_cat(label,
//! slot))`, where the slot is what the record is about. The same slot gives
//! the same key on every device, so a device rewriting a record replaces it,
//! and the key says nothing about the slot to anyone without `K`.
//!
//! **Sealing.** Each value gets a fresh 32-byte salt and a key of its own,
//! `HMAC-SHA-256(K, lv_cat(label, salt))`, used once with AES-256-GCM under
//! the all-zero nonce. With a key per value there is no nonce to repeat, and
//! no limit on how many values one fleet key seals. The associated data is
//! `lv_cat(label, version, bound...)`, where the caller binds the value to
//! its place (the document id and entry key), so a sealed value moved
//! anywhere else no longer opens. The byte form is `version ‖ salt ‖
//! ciphertext ‖ tag`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::PairingError;
use crate::cpace::lv_cat;
use crate::keys::{STORED_KIND_FLEET, StoredKeysError, random_secret, stored_fields, stored_form};
use crate::secret::Secret;

/// Length of the fleet key.
pub const FLEET_KEY_BYTES: usize = 32;
/// Length of an entry key the fleet key names.
pub const ENTRY_KEY_BYTES: usize = 32;
/// The version of the sealed form. There is one.
const SEALED_VERSION: u8 = 1;
/// Length of the salt each sealed value's key is derived from.
const SALT_BYTES: usize = 32;
/// Length of the AES-GCM tag.
const TAG_BYTES: usize = 16;
/// What sealing adds to a value: the version, the salt and the tag.
pub const SEALED_OVERHEAD_BYTES: usize = 1 + SALT_BYTES + TAG_BYTES;

const ENTRY_KEY_LABEL: &[u8] = b"keys fleet entry key";
const VALUE_KEY_LABEL: &[u8] = b"keys fleet value key";
const VALUE_AAD_LABEL: &[u8] = b"keys fleet value";

type HmacSha256 = Hmac<Sha256>;

/// An account's fleet key. Wiped on drop.
#[derive(Debug)]
pub struct FleetKey(Secret<FLEET_KEY_BYTES>);

impl FleetKey {
    /// A fresh fleet key.
    ///
    /// # Errors
    /// [`PairingError::Random`] if the system random source fails.
    pub fn generate() -> Result<Self, PairingError> {
        let key = random_secret()?;
        Ok(Self(Secret::copy_of(&key)))
    }

    /// The stored form: a version, a kind and the key.
    #[must_use]
    pub fn to_stored(&self) -> Zeroizing<Vec<u8>> {
        stored_form(STORED_KIND_FLEET, &[self.0.as_bytes()])
    }

    /// Reads a stored form.
    ///
    /// # Errors
    /// [`StoredKeysError`] if it isn't a fleet key's stored form.
    pub fn from_stored(stored: &[u8]) -> Result<Self, StoredKeysError> {
        let [key] = stored_fields(stored, STORED_KIND_FLEET)?;
        Ok(Self(Secret::copy_of(key)))
    }

    /// The entry key for `slot`.
    #[must_use]
    pub fn entry_key(&self, slot: &[u8]) -> [u8; ENTRY_KEY_BYTES] {
        *self.mac(&lv_cat(&[ENTRY_KEY_LABEL, slot]))
    }

    /// Seals `plaintext` for the place `bound` names.
    ///
    /// # Errors
    /// [`PairingError::Random`] if the system random source fails.
    ///
    /// # Panics
    /// If `plaintext` is longer than AES-GCM allows (64 GiB).
    pub fn seal(&self, bound: &[&[u8]], plaintext: &[u8]) -> Result<Vec<u8>, PairingError> {
        let mut salt = [0u8; SALT_BYTES];
        crate::random::fill(&mut salt).map_err(|_| PairingError::Random)?;
        let ciphertext = self
            .value_cipher(&salt)
            .encrypt(
                &Nonce::default(),
                Payload {
                    msg: plaintext,
                    aad: &value_aad(bound),
                },
            )
            .expect("a fleet value is far below AES-GCM's length limit");
        let mut out = Vec::with_capacity(1 + SALT_BYTES + ciphertext.len());
        out.push(SEALED_VERSION);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens a value sealed for the place `bound` names. `None` if it isn't
    /// a sealed value, wasn't sealed under this key, or was sealed for
    /// another place. The plaintext is wiped when the caller drops it.
    #[must_use]
    pub fn open(&self, bound: &[&[u8]], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let (&[version], rest) = sealed.split_first_chunk::<1>()?;
        if version != SEALED_VERSION {
            return None;
        }
        let (salt, ciphertext) = rest.split_first_chunk::<SALT_BYTES>()?;
        self.value_cipher(salt)
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: ciphertext,
                    aad: &value_aad(bound),
                },
            )
            .ok()
            .map(Zeroizing::new)
    }

    fn mac(&self, message: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut mac =
            HmacSha256::new_from_slice(self.0.as_bytes()).expect("HMAC accepts any key length");
        mac.update(message);
        let mut out = Zeroizing::new([0u8; 32]);
        hmac::digest::FixedOutput::finalize_into(mac, (&mut *out).into());
        out
    }

    /// The cipher for one value, keyed from its salt. Built, used and
    /// dropped within one call.
    fn value_cipher(&self, salt: &[u8; SALT_BYTES]) -> Aes256Gcm {
        let key = self.mac(&lv_cat(&[VALUE_KEY_LABEL, salt]));
        Aes256Gcm::new_from_slice(&*key).expect("a 32-byte key")
    }
}

fn value_aad(bound: &[&[u8]]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(bound.len() + 2);
    parts.push(VALUE_AAD_LABEL);
    parts.push(&[SEALED_VERSION]);
    parts.extend_from_slice(bound);
    lv_cat(&parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::scripted;

    const PLACE: [&[u8]; 2] = [b"doc", b"entry"];

    fn key() -> FleetKey {
        FleetKey(Secret::copy_of(&[0x4b; FLEET_KEY_BYTES]))
    }

    #[test]
    fn a_sealed_value_opens_only_in_its_place_under_its_key() {
        let key = key();
        let sealed = key.seal(&PLACE, b"roster entry").expect("random");
        assert_eq!(sealed.len(), SEALED_OVERHEAD_BYTES + b"roster entry".len());
        assert_eq!(
            key.open(&PLACE, &sealed).as_deref().map(Vec::as_slice),
            Some(&b"roster entry"[..])
        );
        assert!(key.open(&[b"doc", b"other entry"], &sealed).is_none());
        assert!(key.open(&[b"other doc", b"entry"], &sealed).is_none());
        assert!(key.open(&[b"doc"], &sealed).is_none());
        // lv_cat keeps the parts apart: the same bytes split differently
        // are another place.
        assert!(key.open(&[b"docentry"], &sealed).is_none());
        assert!(key.open(&[b"doc", b"entry", b""], &sealed).is_none());
        let other = FleetKey::generate().expect("random");
        assert!(other.open(&PLACE, &sealed).is_none());
    }

    #[test]
    fn every_change_to_a_sealed_value_is_refused() {
        let key = key();
        let sealed = key.seal(&PLACE, b"value").expect("random");
        for index in 0..sealed.len() {
            for bit in 0..8 {
                let mut altered = sealed.clone();
                altered[index] ^= 1 << bit;
                assert!(
                    key.open(&PLACE, &altered).is_none(),
                    "byte {index} bit {bit}"
                );
            }
        }
        for length in 0..sealed.len() {
            assert!(
                key.open(&PLACE, &sealed[..length]).is_none(),
                "cut to {length}"
            );
        }
        let mut longer = sealed.clone();
        longer.push(0);
        assert!(key.open(&PLACE, &longer).is_none());
    }

    #[test]
    fn each_value_has_a_salt_of_its_own() {
        let key = key();
        let first = key.seal(&PLACE, b"same").expect("random");
        let second = key.seal(&PLACE, b"same").expect("random");
        assert_ne!(first[1..=SALT_BYTES], second[1..=SALT_BYTES]);
        assert_ne!(first, second);
    }

    #[test]
    fn entry_keys_are_per_slot_and_per_key() {
        let key = key();
        assert_eq!(key.entry_key(b"slot"), key.entry_key(b"slot"));
        assert_ne!(key.entry_key(b"slot"), key.entry_key(b"slot2"));
        let other = FleetKey::generate().expect("random");
        assert_ne!(key.entry_key(b"slot"), other.entry_key(b"slot"));
    }

    #[test]
    fn the_stored_form_round_trips_and_is_kept_apart_from_other_keys() {
        let key = FleetKey::generate().expect("random");
        let stored = key.to_stored();
        assert_eq!(stored.len(), 2 + FLEET_KEY_BYTES);
        let back = FleetKey::from_stored(&stored).expect("stored form");
        assert_eq!(back.entry_key(b"slot"), key.entry_key(b"slot"));
        let vault = crate::DeviceKeys::generate().expect("random");
        assert_eq!(
            FleetKey::from_stored(&vault.vault_key().to_stored()).unwrap_err(),
            StoredKeysError::WrongKind
        );
        assert_eq!(
            FleetKey::from_stored(&stored[..stored.len() - 1]).unwrap_err(),
            StoredKeysError::Damaged
        );
    }

    #[test]
    fn a_failing_random_source_seals_nothing() {
        scripted::with_seed(b"fleet key", || {
            scripted::set_failing(true);
            assert_eq!(key().seal(&PLACE, b"value"), Err(PairingError::Random));
            assert!(matches!(FleetKey::generate(), Err(PairingError::Random)));
        });
    }

    /// Known answers, recomputed independently from the construction in the
    /// module docs (HMAC-SHA-256, `lv_cat`, AES-256-GCM).
    #[test]
    fn fleet_key_known_answer() {
        let key = key();
        assert_eq!(
            crate::hex::encode(&key.entry_key(b"slot")),
            "b24989b88d408d942ad1f80f2aac22b20c17b0a2f5584633b40d613e23af87bf"
        );
        let sealed = scripted::with_seed(b"fleet key known answer", || {
            key.seal(&PLACE, b"roster entry").expect("scripted random")
        });
        assert_eq!(
            crate::hex::encode(&sealed),
            "016c32090ee796807a8140cb5faaa3617899d693bc8b2c830b716984489aef65d130b3856f1aeda246b318a3b0aae8be996f394b25353282d3cd1096a4"
        );
    }
}
