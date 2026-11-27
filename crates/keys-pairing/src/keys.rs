//! The key sets a pairing binds: one account's keys, and one device's.
//!
//! Account keys (one set per account, the same on all of its devices):
//! - the **identity key** (Ed25519): signs as the account towards People,
//!   certifies its devices and its encryption key;
//! - the **encryption key** (X25519): what People seal envelopes to. Signing
//!   keys are never used for encryption;
//! - the **recovery key** (Ed25519): the offline root. Its secret half exists
//!   only as the recovery secret handed back once at generation, for the
//!   person to record; an [`AccountKeys`] holds only its public half.
//!
//! Device keys (one set per device and account, generated on the device; the
//! private halves never leave it): a **signing key** (Ed25519) and two
//! **encryption keys** (X25519) for the two protection classes: the **relay
//! key**, usable while the device is locked, and the **vault key**, behind
//! the app's unlock. The transport's endpoint identity and the document
//! author keys belong to the sync transport and are not generated here.
//!
//! **What the account identity key signs.** Every signature it makes is over
//! `lv_cat(label, ...)` with a label of its own, so a signature made for one
//! purpose can't be presented for another. Labels in use:
//! - `"keys-pairing person keys"`: a Person pairing's key set (`protocol`).
//!
//! Add each new signing purpose here with a fresh label.
//!
//! This module only generates and holds keys. Where they are stored, and how
//! the recovery secret is rendered for a person to write down, is the
//! caller's business.

use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::PairingError;
use crate::cpace::lv_cat;
use crate::secret::Secret;

/// Length of every public key in these sets (Ed25519 and X25519 alike).
pub const PUBLIC_KEY_BYTES: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;
/// Length of the recovery secret: 128 bits.
pub const RECOVERY_SECRET_BYTES: usize = 16;
/// Length of a private scalar or seed (Ed25519 seed, X25519 secret).
const SECRET_KEY_BYTES: usize = 32;
/// Length of a SHA-512 output, the digest a recovery signing seed is cut
/// from.
const RECOVERY_DIGEST_BYTES: usize = 64;
/// Domain separator for deriving the recovery signing key from the recovery
/// secret.
const RECOVERY_KEY_LABEL: &[u8] = b"keys recovery key v1";

fn random_secret() -> Result<Zeroizing<[u8; SECRET_KEY_BYTES]>, PairingError> {
    let mut bytes = Zeroizing::new([0u8; SECRET_KEY_BYTES]);
    crate::random::fill(bytes.as_mut()).map_err(|_| PairingError::Random)?;
    Ok(bytes)
}

/// A signing key in an allocation of its own (it wipes itself on drop), so
/// moving the key set that holds it moves a pointer, never the seed.
fn boxed_signing_key(seed: &[u8; SECRET_KEY_BYTES]) -> Box<SigningKey> {
    Box::new(SigningKey::from_bytes(seed))
}

fn random_signing_key() -> Result<Box<SigningKey>, PairingError> {
    Ok(boxed_signing_key(&*random_secret()?))
}

/// An X25519 key pair. The secret lives in an allocation of its own and is
/// wiped on drop.
pub struct X25519Secret(Secret<SECRET_KEY_BYTES>);

impl X25519Secret {
    fn generate() -> Result<Self, PairingError> {
        let mut secret = Secret::zeroed();
        crate::random::fill(secret.as_mut()).map_err(|_| PairingError::Random)?;
        Ok(Self(secret))
    }

    /// The public key, `X25519(secret, 9)` (RFC 7748, with its clamping).
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        MontgomeryPoint::mul_base_clamped(*self.0.as_bytes()).to_bytes()
    }
}

/// The recovery secret: 128 random bits from which the recovery signing key is
/// derived. Handed back once, at account generation, and never kept by
/// [`AccountKeys`]. It lives in an allocation of its own, is wiped on drop,
/// and is never printed by `Debug`.
pub struct RecoverySecret(Secret<RECOVERY_SECRET_BYTES>);

impl std::fmt::Debug for RecoverySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoverySecret(<redacted>)")
    }
}

impl RecoverySecret {
    /// The recovery signing key: the Ed25519 seed is the first 32 bytes of
    /// `SHA-512(lv_cat("keys recovery key v1", secret))`.
    #[must_use]
    pub fn signing_key(&self) -> Box<SigningKey> {
        let input = Zeroizing::new(lv_cat(&[RECOVERY_KEY_LABEL, self.0.as_bytes()]));
        let mut digest = Zeroizing::new([0u8; RECOVERY_DIGEST_BYTES]);
        Sha512::new_with_prefix(input.as_slice()).finalize_into((&mut *digest).into());
        let mut seed = Zeroizing::new([0u8; SECRET_KEY_BYTES]);
        seed.copy_from_slice(&digest[..SECRET_KEY_BYTES]);
        boxed_signing_key(&seed)
    }

    /// The recovery secret's raw bytes, for the caller to render as the
    /// recovery code.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; RECOVERY_SECRET_BYTES] {
        self.0.as_bytes()
    }
}

/// An account's public key set: what a Person verifies in a pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountPublicKeys {
    pub identity: [u8; PUBLIC_KEY_BYTES],
    pub recovery: [u8; PUBLIC_KEY_BYTES],
    pub encryption: [u8; PUBLIC_KEY_BYTES],
}

impl AccountPublicKeys {
    /// Whether the recovery and encryption keys are usable keys at all: the
    /// recovery key a valid Ed25519 point that isn't of small order, the
    /// encryption key an X25519 point on the curve (not its twist) that
    /// isn't of small order, so a later key agreement with it can't be
    /// forced to a known shared secret. The identity key
    /// is checked by verifying its signature, strictly.
    #[must_use]
    pub(crate) fn recovery_and_encryption_are_well_formed(&self) -> bool {
        // Either sign choice gives a point of the same order.
        const EDWARDS_SIGN: u8 = 0;
        let recovery_ok = VerifyingKey::from_bytes(&self.recovery).is_ok_and(|key| !key.is_weak());
        let encryption_ok = MontgomeryPoint(self.encryption)
            .to_edwards(EDWARDS_SIGN)
            .is_some_and(|point| !point.is_small_order());
        recovery_ok && encryption_ok
    }
}

/// An account's keys as a device holds them: identity and encryption private
/// keys, and only the public half of the recovery key. Private halves are
/// wiped on drop.
pub struct AccountKeys {
    identity: Box<SigningKey>,
    encryption: X25519Secret,
    recovery_public: [u8; PUBLIC_KEY_BYTES],
}

impl AccountKeys {
    /// Generates a fresh account: identity, encryption and recovery keys. The
    /// recovery secret comes back separately, once; the returned
    /// [`AccountKeys`] doesn't keep it.
    ///
    /// # Errors
    /// [`PairingError::Random`] if the system random source fails.
    pub fn generate() -> Result<(Self, RecoverySecret), PairingError> {
        let mut recovery = RecoverySecret(Secret::zeroed());
        crate::random::fill(recovery.0.as_mut()).map_err(|_| PairingError::Random)?;
        let keys = Self {
            identity: random_signing_key()?,
            encryption: X25519Secret::generate()?,
            recovery_public: recovery.signing_key().verifying_key().to_bytes(),
        };
        Ok((keys, recovery))
    }

    #[must_use]
    pub fn public_keys(&self) -> AccountPublicKeys {
        AccountPublicKeys {
            identity: self.identity.verifying_key().to_bytes(),
            recovery: self.recovery_public,
            encryption: self.encryption.public_key(),
        }
    }

    /// Registers the identity seed and the encryption secret with the
    /// freed-memory watch, by reference, so the test makes no copy of its
    /// own.
    #[cfg(test)]
    pub(crate) fn watch_secrets(&self) {
        crate::heap_watch::register(self.identity.as_bytes());
        crate::heap_watch::register(self.encryption.0.as_bytes());
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_BYTES] {
        self.identity.sign(message).to_bytes()
    }
}

/// Verifies an Ed25519 signature by `public_key` over `message`, strictly
/// (no small-order keys, no malleable signatures).
pub(crate) fn verify_signature(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// A device's public key set: what goes into its roster entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePublicKeys {
    pub signing: [u8; PUBLIC_KEY_BYTES],
    pub relay: [u8; PUBLIC_KEY_BYTES],
    pub vault: [u8; PUBLIC_KEY_BYTES],
}

/// One device's keys. Private halves are wiped on drop.
pub struct DeviceKeys {
    signing: Box<SigningKey>,
    relay: X25519Secret,
    vault: X25519Secret,
}

impl DeviceKeys {
    /// Generates a fresh device key set.
    ///
    /// # Errors
    /// [`PairingError::Random`] if the system random source fails.
    pub fn generate() -> Result<Self, PairingError> {
        Ok(Self {
            signing: random_signing_key()?,
            relay: X25519Secret::generate()?,
            vault: X25519Secret::generate()?,
        })
    }

    #[must_use]
    pub fn public_keys(&self) -> DevicePublicKeys {
        DevicePublicKeys {
            signing: self.signing.verifying_key().to_bytes(),
            relay: self.relay.public_key(),
            vault: self.vault.public_key(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_keys_are_distinct_and_recovery_derives() {
        let (keys, recovery) = AccountKeys::generate().expect("rng");
        let public = keys.public_keys();
        assert_ne!(public.identity, public.recovery);
        assert_ne!(public.identity, public.encryption);
        assert_eq!(
            recovery.signing_key().verifying_key().to_bytes(),
            public.recovery
        );

        let (other, _) = AccountKeys::generate().expect("rng");
        assert_ne!(other.public_keys(), public);
    }

    #[test]
    fn identity_signatures_verify_and_bind_the_message() {
        let (keys, _) = AccountKeys::generate().expect("rng");
        let identity = keys.public_keys().identity;
        let signature = keys.sign(b"message");
        assert!(verify_signature(&identity, b"message", &signature));
        assert!(!verify_signature(&identity, b"messagf", &signature));
        let (other, _) = AccountKeys::generate().expect("rng");
        assert!(!verify_signature(
            &other.public_keys().identity,
            b"message",
            &signature
        ));
    }

    #[test]
    fn device_keys_are_distinct() {
        let device = DeviceKeys::generate().expect("rng");
        let public = device.public_keys();
        assert_ne!(public.relay, public.vault);
        assert_ne!(public.signing, public.relay);
        assert_ne!(DeviceKeys::generate().expect("rng").public_keys(), public);
    }

    /// RFC 7748 §6.1: Alice's X25519 private key and public key.
    #[test]
    fn x25519_public_key_matches_rfc7748() {
        let secret = X25519Secret(Secret::copy_of(&hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        )));
        assert_eq!(
            secret.public_key(),
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
    }

    /// RFC 8032 §7.1 TEST 1: the Ed25519 public key for its secret key.
    #[test]
    fn ed25519_public_key_matches_rfc8032() {
        let key = boxed_signing_key(&hex32(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        assert_eq!(
            key.verifying_key().to_bytes(),
            hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
    }

    #[test]
    fn recovery_secret_debug_is_redacted() {
        let (_, recovery) = AccountKeys::generate().expect("rng");
        assert_eq!(format!("{recovery:?}"), "RecoverySecret(<redacted>)");
    }

    fn hex32(s: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect();
        bytes.try_into().expect("32 bytes")
    }
}
