//! Account identity across the FFI: keeping the account and device keys in
//! the platform's secure storage, the recovery code, and device enrolment.
//!
//! The key objects are pairing's ([`PairingAccountKeys`],
//! [`PairingDeviceKeys`]), since a pairing binds them; this module adds what
//! an account needs of them beyond a pairing.
//!
//! **Where each stored form goes.** One per protection class, so that
//! nothing readable on a locked device can decrypt a vault or act as the
//! account:
//! - [`PairingAccountKeys::stored_form`]: behind the app's unlock;
//! - [`PairingDeviceKeys::sync_stored_form`] (signing and relay keys):
//!   readable after the device's first unlock, device-only;
//! - [`PairingDeviceKeys::vault_stored_form`]: behind the app's unlock.
//!
//! Every stored form is the secret keys themselves, as is the recovery code
//! ([`PairingRecoverySecret::recovery_code`]): the client must not log them,
//! and should drop its copies as soon as they are stored or shown. Rust
//! wipes the byte vectors handed in to the `from_stored` constructors and
//! the typed recovery codes it checks. The stored forms and the recovery
//! code it hands out are plain copies on their way across the FFI: they are
//! freed unwiped, on both sides, as is anything the foreign side holds.

// uniffi exports take owned arguments.
#![allow(clippy::needless_pass_by_value)]

use std::sync::Arc;

use keys_account::{DeviceEnrolment, EnrolmentError, RecoveryCodeError};
use keys_pairing as kp;
use zeroize::Zeroizing;

use crate::pairing::{
    PairingAccountKeys, PairingDeviceKeys, PairingDevicePublicKeys, PairingRecoverySecret,
};

/// Errors from account calls.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AccountFfiError {
    /// A stored form of another kind: the account's handed in as a device's,
    /// say.
    #[error("the stored keys are of another kind")]
    StoredKeysWrongKind,
    /// Not a stored form, or a damaged one.
    #[error("the stored keys are damaged")]
    StoredKeysDamaged,
    /// An endpoint id, author id or public key was not 32 bytes.
    #[error("an id or public key must be 32 bytes")]
    InvalidKeyLength,
    /// Not a device enrolment.
    #[error("not a device enrolment")]
    EnrolmentMalformed,
    /// The enrolment isn't signed by the account it was checked against.
    #[error("the enrolment isn't signed by this account")]
    EnrolmentNotSignedByAccount,
    /// The enrolment names a key that can't be used.
    #[error("the enrolment names a key that can't be used")]
    EnrolmentUnusableKey,
}

impl From<kp::StoredKeysError> for AccountFfiError {
    fn from(error: kp::StoredKeysError) -> Self {
        match error {
            kp::StoredKeysError::WrongKind => Self::StoredKeysWrongKind,
            kp::StoredKeysError::Damaged => Self::StoredKeysDamaged,
        }
    }
}

impl From<EnrolmentError> for AccountFfiError {
    fn from(error: EnrolmentError) -> Self {
        match error {
            EnrolmentError::Malformed => Self::EnrolmentMalformed,
            EnrolmentError::NotSignedByAccount => Self::EnrolmentNotSignedByAccount,
            EnrolmentError::UnusableKey => Self::EnrolmentUnusableKey,
        }
    }
}

fn key32(bytes: &[u8]) -> Result<[u8; kp::keys::PUBLIC_KEY_BYTES], AccountFfiError> {
    bytes
        .try_into()
        .map_err(|_| AccountFfiError::InvalidKeyLength)
}

// ─── account keys ───────────────────────────────────────────────────────────

#[uniffi::export]
impl PairingAccountKeys {
    /// Reads the account's stored form back.
    ///
    /// # Errors
    /// [`AccountFfiError::StoredKeysWrongKind`] or
    /// [`AccountFfiError::StoredKeysDamaged`].
    #[uniffi::constructor]
    pub fn from_stored(stored: Vec<u8>) -> Result<Arc<Self>, AccountFfiError> {
        let stored = Zeroizing::new(stored);
        Ok(Arc::new(Self {
            inner: Arc::new(kp::AccountKeys::from_stored(&stored)?),
        }))
    }

    /// The stored form, for secure storage behind the app's unlock. A
    /// secret: don't log it.
    #[must_use]
    pub fn stored_form(&self) -> Vec<u8> {
        self.inner.to_stored().to_vec()
    }

    /// Checks a typed recovery code against this account: its form, its
    /// check characters, and that it is this account's.
    #[must_use]
    pub fn check_recovery_code(&self, typed: String) -> RecoveryCodeCheck {
        let typed = Zeroizing::new(typed);
        keys_account::check_recovery_code(&typed, &self.inner.public_keys().recovery).into()
    }

    /// Enrols a device into this account: the signed statement for its
    /// roster entry, over its public keys, its transport endpoint id and its
    /// document author id.
    ///
    /// # Errors
    /// [`AccountFfiError::InvalidKeyLength`] for a key or id that isn't 32
    /// bytes; [`AccountFfiError::EnrolmentUnusableKey`] if the device's keys
    /// can't be used.
    pub fn enrol_device(
        &self,
        device: PairingDevicePublicKeys,
        endpoint_id: Vec<u8>,
        author_id: Vec<u8>,
    ) -> Result<Vec<u8>, AccountFfiError> {
        let device = kp::DevicePublicKeys {
            signing: key32(&device.signing)?,
            relay: key32(&device.relay)?,
            vault: key32(&device.vault)?,
        };
        let enrolment = DeviceEnrolment::sign(
            &self.inner,
            device,
            key32(&endpoint_id)?,
            key32(&author_id)?,
        )?;
        Ok(enrolment.to_bytes().to_vec())
    }
}

#[uniffi::export]
impl PairingRecoverySecret {
    /// The recovery code, `XXXX-XXXX-…`, for the person to write down. It is
    /// the secret itself: show it once, never log it.
    #[must_use]
    pub fn recovery_code(&self) -> String {
        keys_account::recovery_code(&self.inner).to_string()
    }
}

/// What a typed recovery code turned out to be. Group numbers count from 1.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCodeCheck {
    /// Well formed and, where it was checked against an account, that
    /// account's.
    Valid,
    /// Not 28 characters, once spaces and hyphens are set aside.
    WrongLength { characters: u64 },
    /// A character that is never in a recovery code, in this group.
    NotInAlphabet { group: u8 },
    /// Most likely a mistyped character in this group.
    Typo { group: u8 },
    /// The checks fail and no single character explains it.
    Unreadable,
    /// A well-formed code, but not this account's.
    NotThisAccount,
}

impl<T> From<Result<T, RecoveryCodeError>> for RecoveryCodeCheck {
    fn from(result: Result<T, RecoveryCodeError>) -> Self {
        match result {
            Ok(_) => Self::Valid,
            // usize is at most 64 bits on every target Rust supports.
            Err(RecoveryCodeError::WrongLength { characters }) => Self::WrongLength {
                characters: characters as u64,
            },
            Err(RecoveryCodeError::NotInAlphabet { group }) => Self::NotInAlphabet { group },
            Err(RecoveryCodeError::Typo { group }) => Self::Typo { group },
            Err(RecoveryCodeError::Unreadable) => Self::Unreadable,
            Err(RecoveryCodeError::NotThisAccount) => Self::NotThisAccount,
        }
    }
}

/// Checks a typed recovery code's form and check characters only, where the
/// account's recovery public key isn't known yet. Never answers
/// [`RecoveryCodeCheck::NotThisAccount`].
#[uniffi::export]
#[must_use]
pub fn read_recovery_code(typed: String) -> RecoveryCodeCheck {
    let typed = Zeroizing::new(typed);
    keys_account::parse_recovery_code(&typed).into()
}

// ─── device keys ────────────────────────────────────────────────────────────

#[uniffi::export]
impl PairingDeviceKeys {
    /// The stored form of the signing and relay keys, for secure storage
    /// readable after the device's first unlock, device-only. A secret:
    /// don't log it.
    #[must_use]
    pub fn sync_stored_form(&self) -> Vec<u8> {
        self.inner.sync_keys().to_stored().to_vec()
    }

    /// The stored form of the vault key, for secure storage behind the app's
    /// unlock. A secret: don't log it.
    #[must_use]
    pub fn vault_stored_form(&self) -> Vec<u8> {
        self.inner.vault_key().to_stored().to_vec()
    }
}

/// A device's signing and relay keys, read back from their stored form.
#[derive(uniffi::Object)]
pub struct DeviceSyncKeys {
    inner: kp::DeviceSyncKeys,
}

#[uniffi::export]
impl DeviceSyncKeys {
    /// # Errors
    /// [`AccountFfiError::StoredKeysWrongKind`] or
    /// [`AccountFfiError::StoredKeysDamaged`].
    #[uniffi::constructor]
    pub fn from_stored(stored: Vec<u8>) -> Result<Arc<Self>, AccountFfiError> {
        let stored = Zeroizing::new(stored);
        Ok(Arc::new(Self {
            inner: kp::DeviceSyncKeys::from_stored(&stored)?,
        }))
    }

    /// The signing public key, which is also the device's id in the account.
    #[must_use]
    pub fn signing_public_key(&self) -> Vec<u8> {
        self.inner.signing_public_key().to_vec()
    }

    #[must_use]
    pub fn relay_public_key(&self) -> Vec<u8> {
        self.inner.relay_public_key().to_vec()
    }
}

/// A device's vault key, read back from its stored form.
#[derive(uniffi::Object)]
pub struct DeviceVaultKey {
    inner: kp::DeviceVaultKey,
}

#[uniffi::export]
impl DeviceVaultKey {
    /// # Errors
    /// [`AccountFfiError::StoredKeysWrongKind`] or
    /// [`AccountFfiError::StoredKeysDamaged`].
    #[uniffi::constructor]
    pub fn from_stored(stored: Vec<u8>) -> Result<Arc<Self>, AccountFfiError> {
        let stored = Zeroizing::new(stored);
        Ok(Arc::new(Self {
            inner: kp::DeviceVaultKey::from_stored(&stored)?,
        }))
    }

    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }
}

// ─── enrolment ──────────────────────────────────────────────────────────────

/// A device enrolment that checked out against its account.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrolmentRecord {
    /// The device's id in the account: its signing public key.
    pub device_id: Vec<u8>,
    pub keys: PairingDevicePublicKeys,
    pub endpoint_id: Vec<u8>,
    pub author_id: Vec<u8>,
}

/// Reads a device enrolment and checks it against the account whose
/// identity key is `account_identity`.
///
/// # Errors
/// [`AccountFfiError::InvalidKeyLength`] if `account_identity` isn't 32
/// bytes; otherwise the enrolment's own refusal.
#[uniffi::export]
pub fn open_device_enrolment(
    enrolment: Vec<u8>,
    account_identity: Vec<u8>,
) -> Result<DeviceEnrolmentRecord, AccountFfiError> {
    let enrolment = DeviceEnrolment::open(&enrolment, &key32(&account_identity)?)?;
    let keys = enrolment.device_keys();
    Ok(DeviceEnrolmentRecord {
        device_id: enrolment.device_id().to_vec(),
        keys: PairingDevicePublicKeys {
            signing: keys.signing.to_vec(),
            relay: keys.relay.to_vec(),
            vault: keys.vault.to_vec(),
        },
        endpoint_id: enrolment.endpoint_id().to_vec(),
        author_id: enrolment.author_id().to_vec(),
    })
}
