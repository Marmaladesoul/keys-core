//! A device's enrolment: the account-signed statement that makes a device
//! one of the account's.
//!
//! Holding an account document's write secret is not enough to add a
//! device. What makes a roster entry valid is this statement, signed by the
//! account identity key over the device's public keys, its transport
//! endpoint id and its document author id. Because it is the signature that
//! counts and not who wrote it down, any device can copy an enrolment into a
//! replacement document.
//!
//! A device's id in the account is its signing public key. Whatever else a
//! device later asserts about itself (when it was last seen, which author it
//! writes a given document under) it signs with that key, and the enrolment
//! is what certifies the key.
//!
//! The byte form is fixed-length: `version ‖ signing ‖ relay ‖ vault ‖
//! endpoint ‖ author ‖ signature`, 225 bytes. The signature is the account
//! identity key's [`SignedStatement::DeviceEnrolment`] over the version and
//! the five keys, each a field of its own. There is no way to hold an
//! enrolment that hasn't been checked: [`DeviceEnrolment::open`] parses and
//! verifies in one step, and an enrolment of unusable keys (not canonically
//! encoded, of small order, off the curve, or one key in two roles) is
//! neither signed nor accepted.

use keys_pairing::keys::{
    PUBLIC_KEY_BYTES, SIGNATURE_BYTES, ed25519_public_key_is_usable, x25519_public_key_is_usable,
};
use keys_pairing::{AccountKeys, DevicePublicKeys, SignedStatement};

/// The version of the enrolment format. There is one.
const ENROLMENT_VERSION: u8 = 1;
/// The public keys an enrolment carries: signing, relay, vault, endpoint,
/// author.
const ENROLMENT_KEYS: usize = 5;
/// Length of an enrolment's byte form.
pub const ENROLMENT_BYTES: usize = 1 + ENROLMENT_KEYS * PUBLIC_KEY_BYTES + SIGNATURE_BYTES;

/// Why an enrolment was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnrolmentError {
    /// Not an enrolment's byte form: the wrong length or version.
    #[error("not a device enrolment")]
    Malformed,
    /// The signature isn't this account's over these keys.
    #[error("the enrolment isn't signed by this account")]
    NotSignedByAccount,
    /// One of the device's keys isn't usable: not canonically encoded, of
    /// small order, off the curve, or the same key in two roles.
    #[error("the enrolment names a key that can't be used")]
    UnusableKey,
}

/// A device enrolment that has been checked: signed by the account it was
/// opened against, with usable keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceEnrolment {
    device: DevicePublicKeys,
    endpoint_id: [u8; PUBLIC_KEY_BYTES],
    author_id: [u8; PUBLIC_KEY_BYTES],
    signature: [u8; SIGNATURE_BYTES],
}

impl DeviceEnrolment {
    /// Enrols the device with public keys `device`, transport endpoint id
    /// `endpoint_id` and document author id `author_id` into `account`.
    ///
    /// # Errors
    /// [`EnrolmentError::UnusableKey`] if the device's keys or ids aren't
    /// usable; nothing is signed.
    pub fn sign(
        account: &AccountKeys,
        device: DevicePublicKeys,
        endpoint_id: [u8; PUBLIC_KEY_BYTES],
        author_id: [u8; PUBLIC_KEY_BYTES],
    ) -> Result<Self, EnrolmentError> {
        check_device_keys(&device, &endpoint_id, &author_id)?;
        let signature = account.sign_statement(
            SignedStatement::DeviceEnrolment,
            &signed_fields(&device, &endpoint_id, &author_id),
        );
        Ok(Self {
            device,
            endpoint_id,
            author_id,
            signature,
        })
    }

    /// Reads an enrolment's byte form and checks it against the account
    /// whose identity key is `account_identity`.
    ///
    /// # Errors
    /// [`EnrolmentError`] if it is malformed, isn't signed by that account,
    /// or names a key that can't be used.
    pub fn open(
        bytes: &[u8],
        account_identity: &[u8; PUBLIC_KEY_BYTES],
    ) -> Result<Self, EnrolmentError> {
        let (&version, rest) = bytes.split_first().ok_or(EnrolmentError::Malformed)?;
        if version != ENROLMENT_VERSION {
            return Err(EnrolmentError::Malformed);
        }
        let (keys, &signature) = rest
            .split_last_chunk::<SIGNATURE_BYTES>()
            .ok_or(EnrolmentError::Malformed)?;
        let (keys, []) = keys.as_chunks::<PUBLIC_KEY_BYTES>() else {
            return Err(EnrolmentError::Malformed);
        };
        let &[signing, relay, vault, endpoint_id, author_id] = keys else {
            return Err(EnrolmentError::Malformed);
        };
        let device = DevicePublicKeys {
            signing,
            relay,
            vault,
        };

        if !SignedStatement::DeviceEnrolment.verify(
            account_identity,
            &signed_fields(&device, &endpoint_id, &author_id),
            &signature,
        ) {
            return Err(EnrolmentError::NotSignedByAccount);
        }
        check_device_keys(&device, &endpoint_id, &author_id)?;
        Ok(Self {
            device,
            endpoint_id,
            author_id,
            signature,
        })
    }

    /// The byte form, for a roster entry.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ENROLMENT_BYTES] {
        let mut out = [0u8; ENROLMENT_BYTES];
        out[0] = ENROLMENT_VERSION;
        let keys = [
            &self.device.signing,
            &self.device.relay,
            &self.device.vault,
            &self.endpoint_id,
            &self.author_id,
        ];
        let (slots, _) = out[1..].as_chunks_mut::<PUBLIC_KEY_BYTES>();
        for (slot, key) in slots.iter_mut().zip(keys) {
            *slot = *key;
        }
        out[1 + ENROLMENT_KEYS * PUBLIC_KEY_BYTES..].copy_from_slice(&self.signature);
        out
    }

    /// The device's id in the account: its signing public key.
    #[must_use]
    pub fn device_id(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.device.signing
    }

    #[must_use]
    pub fn device_keys(&self) -> DevicePublicKeys {
        self.device
    }

    /// The device's transport endpoint id.
    #[must_use]
    pub fn endpoint_id(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.endpoint_id
    }

    /// The author id the device writes the account's documents under.
    #[must_use]
    pub fn author_id(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.author_id
    }
}

/// What the account signs: the format version and each key, as fields of
/// their own.
fn signed_fields<'a>(
    device: &'a DevicePublicKeys,
    endpoint_id: &'a [u8; PUBLIC_KEY_BYTES],
    author_id: &'a [u8; PUBLIC_KEY_BYTES],
) -> [&'a [u8]; 1 + ENROLMENT_KEYS] {
    [
        &[ENROLMENT_VERSION],
        &device.signing,
        &device.relay,
        &device.vault,
        endpoint_id,
        author_id,
    ]
}

/// A device's keys are usable if its signing key, endpoint id and author id
/// are usable Ed25519 keys (the transport's endpoint and author ids are
/// Ed25519 keys too) and three different keys, so no key signs for two
/// protocols; and its relay and vault keys are usable X25519 keys that
/// differ, so the two protection classes stay two. The checks demand
/// canonical encodings, so "differ" compares keys, not spellings.
fn check_device_keys(
    device: &DevicePublicKeys,
    endpoint_id: &[u8; PUBLIC_KEY_BYTES],
    author_id: &[u8; PUBLIC_KEY_BYTES],
) -> Result<(), EnrolmentError> {
    let signing_keys = [&device.signing, endpoint_id, author_id];
    let usable = signing_keys
        .iter()
        .all(|key| ed25519_public_key_is_usable(key))
        && device.signing != *endpoint_id
        && device.signing != *author_id
        && endpoint_id != author_id
        && x25519_public_key_is_usable(&device.relay)
        && x25519_public_key_is_usable(&device.vault)
        && device.relay != device.vault;
    if usable {
        Ok(())
    } else {
        Err(EnrolmentError::UnusableKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keys_pairing::DeviceKeys;

    /// Stand-ins for the transport's endpoint and author ids: any usable
    /// Ed25519 keys, here other devices' signing keys.
    fn transport_ids() -> ([u8; PUBLIC_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]) {
        (
            DeviceKeys::generate().expect("rng").public_keys().signing,
            DeviceKeys::generate().expect("rng").public_keys().signing,
        )
    }

    fn enrolled() -> (AccountKeys, DevicePublicKeys, DeviceEnrolment) {
        let (account, _) = AccountKeys::generate().expect("rng");
        let device = DeviceKeys::generate().expect("rng").public_keys();
        let (endpoint, author) = transport_ids();
        let enrolment = DeviceEnrolment::sign(&account, device, endpoint, author).expect("signs");
        (account, device, enrolment)
    }

    #[test]
    fn an_enrolment_opens_against_its_account() {
        let (account, device, enrolment) = enrolled();
        let opened = DeviceEnrolment::open(&enrolment.to_bytes(), &account.public_keys().identity)
            .expect("opens");
        assert_eq!(opened, enrolment);
        assert_eq!(opened.device_id(), device.signing);
        assert_eq!(opened.device_keys(), device);
        assert_eq!(opened.endpoint_id(), enrolment.endpoint_id());
        assert_eq!(opened.author_id(), enrolment.author_id());
        assert_ne!(opened.endpoint_id(), opened.author_id());
    }

    #[test]
    fn another_account_s_enrolment_is_refused() {
        let (_, _, enrolment) = enrolled();
        let (other, _) = AccountKeys::generate().expect("rng");
        assert_eq!(
            DeviceEnrolment::open(&enrolment.to_bytes(), &other.public_keys().identity),
            Err(EnrolmentError::NotSignedByAccount)
        );
    }

    /// Changing any one bit anywhere after the version byte leaves a
    /// statement the account didn't sign.
    #[test]
    fn every_altered_bit_is_refused() {
        let (account, _, enrolment) = enrolled();
        let identity = account.public_keys().identity;
        let bytes = enrolment.to_bytes();
        for index in 1..ENROLMENT_BYTES {
            for bit in 0..8 {
                let mut altered = bytes;
                altered[index] ^= 1 << bit;
                assert_eq!(
                    DeviceEnrolment::open(&altered, &identity),
                    Err(EnrolmentError::NotSignedByAccount),
                    "byte {index} bit {bit}"
                );
            }
        }
        let mut versioned = bytes;
        versioned[0] = ENROLMENT_VERSION + 1;
        assert_eq!(
            DeviceEnrolment::open(&versioned, &identity),
            Err(EnrolmentError::Malformed)
        );
    }

    #[test]
    fn the_wrong_length_is_refused() {
        let (account, _, enrolment) = enrolled();
        let identity = account.public_keys().identity;
        let bytes = enrolment.to_bytes();
        for len in [0, 1, ENROLMENT_BYTES - 1] {
            assert_eq!(
                DeviceEnrolment::open(&bytes[..len], &identity),
                Err(EnrolmentError::Malformed)
            );
        }
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(
            DeviceEnrolment::open(&long, &identity),
            Err(EnrolmentError::Malformed)
        );
    }

    #[test]
    fn unusable_device_keys_are_never_signed_or_accepted() {
        let (account, _) = AccountKeys::generate().expect("rng");
        let good = DeviceKeys::generate().expect("rng").public_keys();
        let (endpoint, author) = transport_ids();
        let mut small_order = [0u8; PUBLIC_KEY_BYTES];
        small_order[0] = 1;
        // The relay key under another spelling: X25519 ignores the top bit.
        let mut aliased_relay = good.relay;
        aliased_relay[PUBLIC_KEY_BYTES - 1] ^= 0x80;
        let device = |device: DevicePublicKeys| (device, endpoint, author);
        let cases = [
            device(DevicePublicKeys {
                signing: small_order,
                ..good
            }),
            device(DevicePublicKeys {
                relay: [0; PUBLIC_KEY_BYTES],
                ..good
            }),
            device(DevicePublicKeys {
                vault: [0; PUBLIC_KEY_BYTES],
                ..good
            }),
            device(DevicePublicKeys {
                vault: good.relay,
                ..good
            }),
            device(DevicePublicKeys {
                vault: aliased_relay,
                ..good
            }),
            (good, small_order, author),
            (good, endpoint, [0; PUBLIC_KEY_BYTES]),
            (good, good.signing, author),
            (good, endpoint, good.signing),
            (good, endpoint, endpoint),
        ];
        for (index, (device, endpoint, author)) in cases.into_iter().enumerate() {
            assert_eq!(
                DeviceEnrolment::sign(&account, device, endpoint, author),
                Err(EnrolmentError::UnusableKey),
                "case {index}"
            );
            // Even signed by the account, an enrolment of such keys is
            // refused when opened.
            let signature = account.sign_statement(
                SignedStatement::DeviceEnrolment,
                &signed_fields(&device, &endpoint, &author),
            );
            let forged = DeviceEnrolment {
                device,
                endpoint_id: endpoint,
                author_id: author,
                signature,
            };
            assert_eq!(
                DeviceEnrolment::open(&forged.to_bytes(), &account.public_keys().identity),
                Err(EnrolmentError::UnusableKey),
                "case {index}"
            );
        }
    }

    /// An enrolment's byte form, pinned: the account and device are read
    /// from literal stored forms, the transport ids are fixed keys, and
    /// Ed25519 signing is deterministic, so the whole 225 bytes are fixed.
    /// Computed independently of this crate.
    #[test]
    fn enrolment_known_answer() {
        use keys_pairing::{DeviceSyncKeys, DeviceVaultKey, RecoverySecret};
        let stored = |kind: u8, fields: &[[u8; PUBLIC_KEY_BYTES]]| {
            let mut form = vec![0x01, kind];
            for field in fields {
                form.extend_from_slice(field);
            }
            form
        };
        let recovery_public = RecoverySecret::from_bytes(&[0x33; 16]).public_key();
        let account =
            AccountKeys::from_stored(&stored(b'A', &[[0x11; 32], [0x22; 32], recovery_public]))
                .expect("account form");
        let sync = DeviceSyncKeys::from_stored(&stored(b'S', &[[0x44; 32], [0x55; 32]]))
            .expect("sync form");
        let vault = DeviceVaultKey::from_stored(&stored(b'V', &[[0x66; 32]])).expect("vault form");
        let device = DevicePublicKeys {
            signing: sync.signing_public_key(),
            relay: sync.relay_public_key(),
            vault: vault.public_key(),
        };
        let enrolment = DeviceEnrolment::sign(
            &account,
            device,
            unhex(KAT_ENDPOINT).try_into().expect("32 bytes"),
            unhex(KAT_AUTHOR).try_into().expect("32 bytes"),
        )
        .expect("signs");
        assert_eq!(enrolment.to_bytes().as_slice(), unhex(KAT_ENROLMENT));
        assert_eq!(
            DeviceEnrolment::open(&unhex(KAT_ENROLMENT), &account.public_keys().identity),
            Ok(enrolment)
        );
    }

    /// Public keys of the Ed25519 seeds `[0x77; 32]` and `[0x88; 32]`.
    const KAT_ENDPOINT: &str = "c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7";
    const KAT_AUTHOR: &str = "b2491d9502ae28630a2bacb2e0c74510ffcdd328c334ff3e1393e75b2d31e7dc";
    const KAT_ENROLMENT: &str = concat!(
        "01",
        "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48",
        "38ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c67",
        "219e4d800da968d2a5fcb009c784f4746c7138edb9ee4844b739e830b05cf424",
        "c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7",
        "b2491d9502ae28630a2bacb2e0c74510ffcdd328c334ff3e1393e75b2d31e7dc",
        "00c3fa0447ed04ab5887c793456cc29f8df52c4bb71a2e15150e577b4bd4be37",
        "bf21398e204f0c620cd29bb0ddce2433d378f154f1ec58d3543ee13ea1a83504",
    );

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// The account's signature over an enrolment is no other statement's.
    #[test]
    fn an_enrolment_signature_is_only_an_enrolment() {
        let (account, device, enrolment) = enrolled();
        let identity = account.public_keys().identity;
        let (endpoint, author) = (enrolment.endpoint_id(), enrolment.author_id());
        let fields = signed_fields(&device, &endpoint, &author);
        let signature = enrolment.to_bytes()[1 + ENROLMENT_KEYS * PUBLIC_KEY_BYTES..]
            .try_into()
            .expect("64 bytes");
        assert!(SignedStatement::DeviceEnrolment.verify(&identity, &fields, &signature));
        assert!(!SignedStatement::PersonKeys.verify(&identity, &fields, &signature));
    }
}
