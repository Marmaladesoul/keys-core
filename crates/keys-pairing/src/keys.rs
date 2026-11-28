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
//! `lv_cat(label, fields...)` for one [`SignedStatement`], each with a label
//! of its own, so a signature made for one purpose can't be presented for
//! another. The enum is the whole list: a new purpose is a new variant with a
//! fresh label, and there is no way to sign anything else.
//!
//! **Stored forms.** Each key set has a byte form for the platform's secure
//! storage, one per protection class, so nothing readable on a locked device
//! can decrypt a vault or act as the account:
//! - [`AccountKeys::to_stored`]: behind the app's unlock;
//! - [`DeviceSyncKeys::to_stored`] (signing and relay keys): readable after
//!   the device's first unlock, so an unattended device can keep syncing;
//! - [`DeviceVaultKey::to_stored`]: behind the app's unlock.
//!
//! A stored form is `[version, kind]` followed by the 32-byte secrets (and,
//! for an account, the recovery public key). It is a secret: it is handed
//! back wiped-on-drop, and the caller must not log it.
//!
//! This module only generates, holds and serialises keys. Where the stored
//! forms are kept, and how the recovery secret is rendered for a person to
//! write down, is the caller's business.

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

/// The version of every stored form. There is one; a form of any other
/// version is refused as damaged.
const STORED_FORMAT_VERSION: u8 = 1;
/// What a stored form holds, so one kept in the wrong place is refused
/// rather than read as another kind.
const STORED_KIND_ACCOUNT: u8 = b'A';
const STORED_KIND_DEVICE_SYNC: u8 = b'S';
const STORED_KIND_DEVICE_VAULT: u8 = b'V';
/// Length of a stored form's header: the version and the kind.
const STORED_HEADER_BYTES: usize = 2;

/// Why a stored form was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoredKeysError {
    /// It is a well-formed stored form of another kind.
    #[error("the stored keys are of another kind")]
    WrongKind,
    /// It is not a stored form at all, or one that is damaged.
    #[error("the stored keys are damaged")]
    Damaged,
}

/// Everything the account identity key signs. Each statement is signed over
/// `lv_cat(label, fields...)` with a label of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedStatement {
    /// A Person pairing's key set, as one role of one exchange (`protocol`).
    PersonKeys,
    /// A device's enrolment in the account: its public keys, its endpoint id
    /// and its document author id.
    DeviceEnrolment,
}

impl SignedStatement {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::PersonKeys => b"keys-pairing person keys",
            Self::DeviceEnrolment => b"keys account device enrolment",
        }
    }

    /// The bytes signed for this statement over `fields`.
    pub(crate) fn message(self, fields: &[&[u8]]) -> Vec<u8> {
        let mut parts = Vec::with_capacity(fields.len() + 1);
        parts.push(self.label());
        parts.extend_from_slice(fields);
        lv_cat(&parts)
    }

    /// Whether `signature` is the account identity key `identity`'s
    /// signature of this statement over `fields`, verified strictly.
    #[must_use]
    pub fn verify(
        self,
        identity: &[u8; PUBLIC_KEY_BYTES],
        fields: &[&[u8]],
        signature: &[u8; SIGNATURE_BYTES],
    ) -> bool {
        verify_signature(identity, &self.message(fields), signature)
    }
}

/// Whether `key` is a usable Ed25519 public key: a valid point that isn't of
/// small order.
#[must_use]
pub fn ed25519_public_key_is_usable(key: &[u8; PUBLIC_KEY_BYTES]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| !key.is_weak())
}

/// Whether `key` is a usable X25519 public key: a point on the curve (not its
/// twist) that isn't of small order, so a key agreement with it can't be
/// forced to a known shared secret.
#[must_use]
pub fn x25519_public_key_is_usable(key: &[u8; PUBLIC_KEY_BYTES]) -> bool {
    // Either sign choice gives a point of the same order.
    const EDWARDS_SIGN: u8 = 0;
    MontgomeryPoint(*key)
        .to_edwards(EDWARDS_SIGN)
        .is_some_and(|point| !point.is_small_order())
}

/// A stored form of `kind` holding `fields`, in an allocation sized once so
/// it never moves while it is written.
fn stored_form(kind: u8, fields: &[&[u8; SECRET_KEY_BYTES]]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        STORED_HEADER_BYTES + fields.len() * SECRET_KEY_BYTES,
    ));
    out.extend_from_slice(&[STORED_FORMAT_VERSION, kind]);
    for field in fields {
        out.extend_from_slice(*field);
    }
    out
}

/// The `N` 32-byte fields of a stored form of `kind`, borrowed from it.
fn stored_fields<const N: usize>(
    stored: &[u8],
    kind: u8,
) -> Result<[&[u8; SECRET_KEY_BYTES]; N], StoredKeysError> {
    let (header, body) = stored
        .split_at_checked(STORED_HEADER_BYTES)
        .ok_or(StoredKeysError::Damaged)?;
    if header[0] != STORED_FORMAT_VERSION {
        return Err(StoredKeysError::Damaged);
    }
    if ![
        STORED_KIND_ACCOUNT,
        STORED_KIND_DEVICE_SYNC,
        STORED_KIND_DEVICE_VAULT,
    ]
    .contains(&header[1])
    {
        return Err(StoredKeysError::Damaged);
    }
    if header[1] != kind {
        return Err(StoredKeysError::WrongKind);
    }
    let (fields, rest) = body.as_chunks::<SECRET_KEY_BYTES>();
    if fields.len() != N || !rest.is_empty() {
        return Err(StoredKeysError::Damaged);
    }
    Ok(std::array::from_fn(|index| &fields[index]))
}

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

    fn copy_of(bytes: &[u8; SECRET_KEY_BYTES]) -> Self {
        Self(Secret::copy_of(bytes))
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
    /// The recovery secret with these bytes: a recovery code read back in.
    /// The caller still owns, and must wipe, `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; RECOVERY_SECRET_BYTES]) -> Self {
        Self(Secret::copy_of(bytes))
    }

    /// The recovery public key, which every device of the account holds.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.signing_key().verifying_key().to_bytes()
    }

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
        ed25519_public_key_is_usable(&self.recovery)
            && x25519_public_key_is_usable(&self.encryption)
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
            recovery_public: recovery.public_key(),
        };
        Ok((keys, recovery))
    }

    /// The stored form: identity seed, encryption secret, recovery public
    /// key. Behind the app's unlock.
    #[must_use]
    pub fn to_stored(&self) -> Zeroizing<Vec<u8>> {
        stored_form(
            STORED_KIND_ACCOUNT,
            &[
                self.identity.as_bytes(),
                self.encryption.0.as_bytes(),
                &self.recovery_public,
            ],
        )
    }

    /// Reads a stored form back. The caller still owns, and must wipe,
    /// `stored`.
    ///
    /// # Errors
    /// [`StoredKeysError`] if `stored` isn't an account's stored form, or its
    /// recovery public key isn't a usable key.
    pub fn from_stored(stored: &[u8]) -> Result<Self, StoredKeysError> {
        let [identity, encryption, recovery_public] = stored_fields(stored, STORED_KIND_ACCOUNT)?;
        if !ed25519_public_key_is_usable(recovery_public) {
            return Err(StoredKeysError::Damaged);
        }
        Ok(Self {
            identity: boxed_signing_key(identity),
            encryption: X25519Secret::copy_of(encryption),
            recovery_public: *recovery_public,
        })
    }

    /// Signs `statement` over `fields` with the identity key.
    #[must_use]
    pub fn sign_statement(
        &self,
        statement: SignedStatement,
        fields: &[&[u8]],
    ) -> [u8; SIGNATURE_BYTES] {
        self.sign(&statement.message(fields))
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

/// One device's keys, as generated. Private halves are wiped on drop.
///
/// The keys belong to two protection classes, so they are stored, and can be
/// held, apart: [`DeviceSyncKeys`] (readable after the device's first
/// unlock) and [`DeviceVaultKey`] (behind the app's unlock).
pub struct DeviceKeys {
    sync: DeviceSyncKeys,
    vault: DeviceVaultKey,
}

impl DeviceKeys {
    /// Generates a fresh device key set.
    ///
    /// # Errors
    /// [`PairingError::Random`] if the system random source fails.
    pub fn generate() -> Result<Self, PairingError> {
        Ok(Self {
            sync: DeviceSyncKeys {
                signing: random_signing_key()?,
                relay: X25519Secret::generate()?,
            },
            vault: DeviceVaultKey(X25519Secret::generate()?),
        })
    }

    #[must_use]
    pub fn public_keys(&self) -> DevicePublicKeys {
        DevicePublicKeys {
            signing: self.sync.signing_public_key(),
            relay: self.sync.relay_public_key(),
            vault: self.vault.public_key(),
        }
    }

    #[must_use]
    pub fn sync_keys(&self) -> &DeviceSyncKeys {
        &self.sync
    }

    #[must_use]
    pub fn vault_key(&self) -> &DeviceVaultKey {
        &self.vault
    }
}

/// A device's signing and relay keys: what it needs to keep syncing while
/// the app is locked. Readable after the device's first unlock.
pub struct DeviceSyncKeys {
    signing: Box<SigningKey>,
    relay: X25519Secret,
}

impl DeviceSyncKeys {
    /// The signing public key, which is also the device's id in the account.
    #[must_use]
    pub fn signing_public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.signing.verifying_key().to_bytes()
    }

    #[must_use]
    pub fn relay_public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.relay.public_key()
    }

    /// The stored form: signing seed, relay secret.
    #[must_use]
    pub fn to_stored(&self) -> Zeroizing<Vec<u8>> {
        stored_form(
            STORED_KIND_DEVICE_SYNC,
            &[self.signing.as_bytes(), self.relay.0.as_bytes()],
        )
    }

    /// Reads a stored form back. The caller still owns, and must wipe,
    /// `stored`.
    ///
    /// # Errors
    /// [`StoredKeysError`] if `stored` isn't a device's stored sync keys.
    pub fn from_stored(stored: &[u8]) -> Result<Self, StoredKeysError> {
        let [signing, relay] = stored_fields(stored, STORED_KIND_DEVICE_SYNC)?;
        Ok(Self {
            signing: boxed_signing_key(signing),
            relay: X25519Secret::copy_of(relay),
        })
    }

    #[cfg(test)]
    fn watch_secrets(&self) {
        crate::heap_watch::register(self.signing.as_bytes());
        crate::heap_watch::register(self.relay.0.as_bytes());
    }
}

/// A device's vault key: what opens the vault secrets sealed to the device.
/// Behind the app's unlock.
pub struct DeviceVaultKey(X25519Secret);

impl DeviceVaultKey {
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.0.public_key()
    }

    /// The stored form: the vault secret.
    #[must_use]
    pub fn to_stored(&self) -> Zeroizing<Vec<u8>> {
        stored_form(STORED_KIND_DEVICE_VAULT, &[self.0.0.as_bytes()])
    }

    /// Reads a stored form back. The caller still owns, and must wipe,
    /// `stored`.
    ///
    /// # Errors
    /// [`StoredKeysError`] if `stored` isn't a device's stored vault key.
    pub fn from_stored(stored: &[u8]) -> Result<Self, StoredKeysError> {
        let [vault] = stored_fields(stored, STORED_KIND_DEVICE_VAULT)?;
        Ok(Self(X25519Secret::copy_of(vault)))
    }

    #[cfg(test)]
    fn watch_secrets(&self) {
        crate::heap_watch::register(self.0.0.as_bytes());
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
    fn account_keys_survive_their_stored_form() {
        let (keys, recovery) = AccountKeys::generate().expect("rng");
        let stored = keys.to_stored();
        let restored = AccountKeys::from_stored(&stored).expect("restores");
        assert_eq!(restored.public_keys(), keys.public_keys());
        assert_eq!(restored.public_keys().recovery, recovery.public_key());
        // The restored identity key signs as the original.
        let signature = restored.sign_statement(SignedStatement::DeviceEnrolment, &[b"x"]);
        assert!(SignedStatement::DeviceEnrolment.verify(
            &keys.public_keys().identity,
            &[b"x"],
            &signature
        ));
    }

    #[test]
    fn device_keys_survive_their_stored_forms_apart() {
        let device = DeviceKeys::generate().expect("rng");
        let public = device.public_keys();
        let sync = DeviceSyncKeys::from_stored(&device.sync_keys().to_stored()).expect("sync");
        let vault = DeviceVaultKey::from_stored(&device.vault_key().to_stored()).expect("vault");
        assert_eq!(sync.signing_public_key(), public.signing);
        assert_eq!(sync.relay_public_key(), public.relay);
        assert_eq!(vault.public_key(), public.vault);
    }

    #[test]
    fn a_stored_form_of_another_kind_is_refused_as_such() {
        let (account, _) = AccountKeys::generate().expect("rng");
        let device = DeviceKeys::generate().expect("rng");
        let account_form = account.to_stored();
        let sync_form = device.sync_keys().to_stored();
        let vault_form = device.vault_key().to_stored();
        assert_eq!(
            DeviceVaultKey::from_stored(&account_form).err(),
            Some(StoredKeysError::WrongKind)
        );
        assert_eq!(
            AccountKeys::from_stored(&sync_form).err(),
            Some(StoredKeysError::WrongKind)
        );
        assert_eq!(
            DeviceSyncKeys::from_stored(&vault_form).err(),
            Some(StoredKeysError::WrongKind)
        );
    }

    #[test]
    fn a_damaged_stored_form_is_refused() {
        let (account, _) = AccountKeys::generate().expect("rng");
        let form = account.to_stored();
        // Every truncation, and one byte too many.
        for len in 0..form.len() {
            assert_eq!(
                AccountKeys::from_stored(&form[..len]).err(),
                Some(StoredKeysError::Damaged),
                "length {len}"
            );
        }
        let mut long = form.to_vec();
        long.push(0);
        assert_eq!(
            AccountKeys::from_stored(&long).err(),
            Some(StoredKeysError::Damaged)
        );
        // Another version, and an unknown kind.
        for (index, value) in [(0, STORED_FORMAT_VERSION + 1), (1, b'?')] {
            let mut bad = form.to_vec();
            bad[index] = value;
            assert_eq!(
                AccountKeys::from_stored(&bad).err(),
                Some(StoredKeysError::Damaged)
            );
        }
        // A recovery public key that isn't a usable key (the identity point).
        let mut weak = form.to_vec();
        let recovery = STORED_HEADER_BYTES + 2 * SECRET_KEY_BYTES;
        weak[recovery..].copy_from_slice(&IDENTITY_POINT);
        assert_eq!(
            AccountKeys::from_stored(&weak).err(),
            Some(StoredKeysError::Damaged)
        );
    }

    #[test]
    fn stored_forms_leave_no_secret_in_freed_memory() {
        crate::heap_watch::start();
        let (account, _) = AccountKeys::generate().expect("rng");
        account.watch_secrets();
        let device = DeviceKeys::generate().expect("rng");
        device.sync_keys().watch_secrets();
        device.vault_key().watch_secrets();
        let account_form = account.to_stored();
        let sync_form = device.sync_keys().to_stored();
        let vault_form = device.vault_key().to_stored();
        let restored = (
            AccountKeys::from_stored(&account_form).expect("account"),
            DeviceSyncKeys::from_stored(&sync_form).expect("sync"),
            DeviceVaultKey::from_stored(&vault_form).expect("vault"),
        );
        drop((
            account_form,
            sync_form,
            vault_form,
            restored,
            account,
            device,
        ));
        assert_eq!(
            crate::heap_watch::finish(),
            0,
            "a block was freed holding a secret"
        );
    }

    #[test]
    fn a_recovery_secret_read_back_derives_the_same_key() {
        let (keys, recovery) = AccountKeys::generate().expect("rng");
        let read_back = RecoverySecret::from_bytes(recovery.as_bytes());
        assert_eq!(read_back.public_key(), keys.public_keys().recovery);
    }

    #[test]
    fn a_statement_signature_doesnt_verify_as_another_statement() {
        let (keys, _) = AccountKeys::generate().expect("rng");
        let identity = keys.public_keys().identity;
        let fields: [&[u8]; 2] = [b"one", b"two"];
        let signature = keys.sign_statement(SignedStatement::DeviceEnrolment, &fields);
        assert!(SignedStatement::DeviceEnrolment.verify(&identity, &fields, &signature));
        assert!(!SignedStatement::PersonKeys.verify(&identity, &fields, &signature));
        // The fields are length-prefixed: moving a byte across a boundary
        // is a different statement.
        assert!(!SignedStatement::DeviceEnrolment.verify(&identity, &[b"onet", b"wo"], &signature));
    }

    #[test]
    fn public_key_checks_refuse_small_order_points() {
        assert!(!ed25519_public_key_is_usable(&IDENTITY_POINT));
        assert!(!x25519_public_key_is_usable(&[0; PUBLIC_KEY_BYTES]));
        let (keys, _) = AccountKeys::generate().expect("rng");
        let public = keys.public_keys();
        assert!(ed25519_public_key_is_usable(&public.identity));
        assert!(x25519_public_key_is_usable(&public.encryption));
    }

    /// The Edwards identity point's encoding: a valid point of small order.
    const IDENTITY_POINT: [u8; PUBLIC_KEY_BYTES] = {
        let mut point = [0u8; PUBLIC_KEY_BYTES];
        point[0] = 1;
        point
    };

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
