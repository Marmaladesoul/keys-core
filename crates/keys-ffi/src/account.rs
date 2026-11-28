//! Account identity across the FFI: keeping the account and device keys in
//! the platform's secure storage, the recovery code, device enrolment, and
//! the device-signed head records of a vault document.
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

use keys_account::statement::DOC_ID_BYTES;
use keys_account::vault_head::{CONTENT_HASH_BYTES, VAULT_COPY_KEY, VAULT_HEAD_KEY};
use keys_account::{
    DeviceEnrolment, EnrolmentError, HeadIgnored, HeadRefused, RecoveryCodeError, Roster,
    RosterError, StatementError, VaultHead,
};
use keys_pairing as kp;
use zeroize::Zeroizing;

use crate::pairing::{
    PairingAccountKeys, PairingDeviceKeys, PairingDevicePublicKeys, PairingRecoverySecret,
};

/// Errors from account calls.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AccountFfiError {
    /// A stored form tagged as another kind, the account's handed in as a
    /// device's, say, whether or not it is intact.
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
    /// Two enrolments in a roster share a device id, endpoint id or author
    /// id.
    #[error("two enrolments share a key")]
    RosterSharedKey,
    /// A vault id that isn't 16 bytes.
    #[error("a vault id must be 16 bytes")]
    InvalidVaultIdLength,
    /// A fleet record that can't be written as given: a name with nothing
    /// visible in it, an identifier that isn't lower-case ASCII, a field
    /// over its limit, or an account record that isn't one.
    #[error("the fleet record can't be written as given")]
    FleetRecordInvalid,
    /// An account record (a tombstone or vault epoch) not signed by the
    /// account it was checked against.
    #[error("the record isn't signed by this account")]
    FleetRecordNotSignedByAccount,
    /// The system random source failed.
    #[error("the system random source failed")]
    Random,
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

impl From<RosterError> for AccountFfiError {
    fn from(error: RosterError) -> Self {
        match error {
            RosterError::Enrolment(error) => error.into(),
            RosterError::SharedKey => Self::RosterSharedKey,
        }
    }
}

/// A 32-byte id or key: a public key, an author or document id, a content
/// hash. All four are 32 bytes in this format.
pub(crate) fn key32(bytes: &[u8]) -> Result<[u8; kp::keys::PUBLIC_KEY_BYTES], AccountFfiError> {
    crate::pairing::key32_or(bytes, AccountFfiError::InvalidKeyLength)
}

const _: () = assert!(DOC_ID_BYTES == kp::keys::PUBLIC_KEY_BYTES);
const _: () = assert!(CONTENT_HASH_BYTES == kp::keys::PUBLIC_KEY_BYTES);

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
        keys_account::check_recovery_code(&typed, &self.inner.recovery_public_key()).into()
    }

    /// Enrols a device into this account: the signed statement for its
    /// roster entry, over its public keys, its transport endpoint id and its
    /// document author id.
    ///
    /// Enrol a device's keys once. Enrolments carry no sequence, so a second
    /// enrolment sharing the device's signing key, endpoint id or author id
    /// with the first clashes with it for good in the fleet document (both
    /// are refused, and anyone with the fleet key can put the first back).
    /// To enrol a device again, remove it and enrol new keys.
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
    /// Not 28 characters, once spaces, hyphens and dashes are set aside.
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
    pub(crate) inner: kp::DeviceSyncKeys,
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

    /// This device's head record for its copy of a vault in document
    /// `doc_id`: the copy's `content_hash` and `size_bytes`, signed with
    /// sequence `sequence` (see [`next_statement_sequence`]). Write it under
    /// [`vault_head_entry_key`], and the copy itself under
    /// [`vault_copy_entry_key`], both with this device's author.
    ///
    /// # Errors
    /// [`AccountFfiError::InvalidKeyLength`] if `doc_id` or `content_hash`
    /// isn't 32 bytes.
    pub fn sign_vault_head(
        &self,
        doc_id: Vec<u8>,
        sequence: u64,
        content_hash: Vec<u8>,
        size_bytes: u64,
    ) -> Result<Vec<u8>, AccountFfiError> {
        Ok(keys_account::sign_vault_head(
            &self.inner,
            &key32(&doc_id)?,
            sequence,
            VaultHead {
                content_hash: key32(&content_hash)?,
                size: size_bytes,
            },
        ))
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
    Ok((&enrolment).into())
}

impl From<&DeviceEnrolment> for DeviceEnrolmentRecord {
    fn from(enrolment: &DeviceEnrolment) -> Self {
        let keys = enrolment.device_keys();
        Self {
            device_id: enrolment.device_id().to_vec(),
            keys: PairingDevicePublicKeys {
                signing: keys.signing.to_vec(),
                relay: keys.relay.to_vec(),
                vault: keys.vault.to_vec(),
            },
            endpoint_id: enrolment.endpoint_id().to_vec(),
            author_id: enrolment.author_id().to_vec(),
        }
    }
}

// ─── vault document heads ───────────────────────────────────────────────────

/// The entry key every device writes its head record under in a vault
/// document. Entries are kept per author and key, so all devices share it.
#[uniffi::export]
#[must_use]
pub fn vault_head_entry_key() -> Vec<u8> {
    VAULT_HEAD_KEY.to_vec()
}

/// The entry key every device writes its copy of the vault under.
#[uniffi::export]
#[must_use]
pub fn vault_copy_entry_key() -> Vec<u8> {
    VAULT_COPY_KEY.to_vec()
}

/// The sequence for this device's next statement in a place: above
/// `previous` (the sequence of its last statement there, if it knows it,
/// say from its own head read back from the document) and no lower than
/// `now_micros`, its clock in microseconds since the Unix epoch. `None` once
/// `previous` is the last sequence there is: nothing more can be published
/// in that place.
#[uniffi::export]
#[must_use]
pub fn next_statement_sequence(previous: Option<u64>, now_micros: u64) -> Option<u64> {
    keys_account::next_sequence(previous, now_micros)
}

/// The devices of one account, each from an enrolment checked against the
/// account identity key: what binds a document author to a device.
#[derive(uniffi::Object)]
pub struct AccountRoster {
    inner: Roster,
}

impl AccountRoster {
    pub(crate) fn from_roster(inner: Roster) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

/// Whether to fetch an entry as a head record.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum VaultHeadFetch {
    /// Fetch it (within the size the entry records), then check it with
    /// [`AccountRoster::accept_vault_head`]. `device_id` is the device its
    /// author is bound to.
    Fetch { device_id: Vec<u8> },
    /// Leave it unfetched.
    Ignore { reason: VaultHeadIgnored },
}

/// Why an entry is left unfetched.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultHeadIgnored {
    /// Not under the head entry key.
    NotAHead,
    /// Written by an author no device in the roster is bound to.
    UnboundAuthor,
    /// It records a size no head can have.
    TooLarge,
}

/// The result of checking a fetched head record.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum VaultHeadCheck {
    /// Act on it: fetch the copy by `content_hash`, with `size_bytes` as the
    /// fetch's cap, and once the copy has arrived keep `sequence` as the
    /// last accepted from `device_id` in this document (not before: a copy
    /// that didn't arrive leaves the head to be read again). `device_id` is
    /// the copy's owner.
    Accepted {
        device_id: Vec<u8>,
        sequence: u64,
        content_hash: Vec<u8>,
        size_bytes: u64,
    },
    /// Ignore it.
    Refused { reason: VaultHeadRefusal },
}

/// Why a fetched head record was refused.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultHeadRefusal {
    /// Not a statement's byte form.
    Malformed,
    /// Not signed by its signer for this document's head: forged, damaged,
    /// or moved from another document.
    NotSigned,
    /// Written by an author no device in the roster is bound to.
    UnboundAuthor,
    /// A statement, but not a head.
    NotAHead,
    /// Signed by a device other than the one its author is bound to.
    NotItsDevice,
    /// Not newer than the last head accepted from that device here.
    NotNewer,
    /// It names a copy over the caller's cap.
    CopyTooLarge,
}

impl From<HeadIgnored> for VaultHeadIgnored {
    fn from(reason: HeadIgnored) -> Self {
        match reason {
            HeadIgnored::NotAHead => Self::NotAHead,
            HeadIgnored::UnboundAuthor => Self::UnboundAuthor,
            HeadIgnored::TooLarge => Self::TooLarge,
        }
    }
}

impl From<HeadRefused> for VaultHeadRefusal {
    fn from(reason: HeadRefused) -> Self {
        match reason {
            HeadRefused::Statement(StatementError::Malformed | StatementError::TooLarge) => {
                Self::Malformed
            }
            HeadRefused::Statement(StatementError::NotSigned) => Self::NotSigned,
            HeadRefused::UnboundAuthor => Self::UnboundAuthor,
            HeadRefused::NotAHead => Self::NotAHead,
            HeadRefused::NotItsDevice => Self::NotItsDevice,
            HeadRefused::NotNewer => Self::NotNewer,
            HeadRefused::CopyTooLarge => Self::CopyTooLarge,
        }
    }
}

#[uniffi::export]
impl AccountRoster {
    /// Opens each of `enrolments` against the account whose identity key is
    /// `account_identity`. One refused enrolment refuses the whole roster.
    ///
    /// # Errors
    /// [`AccountFfiError::InvalidKeyLength`] if `account_identity` isn't 32
    /// bytes; an enrolment's own refusal; or
    /// [`AccountFfiError::RosterSharedKey`].
    #[uniffi::constructor]
    pub fn open(
        account_identity: Vec<u8>,
        enrolments: Vec<Vec<u8>>,
    ) -> Result<Arc<Self>, AccountFfiError> {
        Ok(Arc::new(Self {
            inner: Roster::open(
                &key32(&account_identity)?,
                enrolments.iter().map(Vec::as_slice),
            )?,
        }))
    }

    /// Step one, from an entry's metadata alone: whether the entry at
    /// `entry_key`, written by `author` and recording `size_bytes`, is to be
    /// fetched as a head record.
    ///
    /// # Errors
    /// [`AccountFfiError::InvalidKeyLength`] if `author` isn't 32 bytes.
    pub fn head_to_fetch(
        &self,
        author: Vec<u8>,
        entry_key: Vec<u8>,
        size_bytes: u64,
    ) -> Result<VaultHeadFetch, AccountFfiError> {
        Ok(
            match keys_account::head_to_fetch(&self.inner, &key32(&author)?, &entry_key, size_bytes)
            {
                Ok(device_id) => VaultHeadFetch::Fetch {
                    device_id: device_id.to_vec(),
                },
                Err(reason) => VaultHeadFetch::Ignore {
                    reason: reason.into(),
                },
            },
        )
    }

    /// Step two: whether `head`, the content of a head entry in document
    /// `doc_id` written by `author`, is one to act on. `last_accepted` is
    /// the sequence of the last head accepted from the same device in this
    /// document; `max_copy_bytes` is the most the caller will fetch for a
    /// copy.
    ///
    /// # Errors
    /// [`AccountFfiError::InvalidKeyLength`] if `doc_id` or `author` isn't
    /// 32 bytes.
    pub fn accept_vault_head(
        &self,
        doc_id: Vec<u8>,
        author: Vec<u8>,
        head: Vec<u8>,
        last_accepted: Option<u64>,
        max_copy_bytes: u64,
    ) -> Result<VaultHeadCheck, AccountFfiError> {
        Ok(
            match keys_account::accept_vault_head(
                &self.inner,
                &key32(&doc_id)?,
                &key32(&author)?,
                &head,
                last_accepted,
                max_copy_bytes,
            ) {
                Ok(accepted) => VaultHeadCheck::Accepted {
                    device_id: accepted.device_id.to_vec(),
                    sequence: accepted.sequence,
                    content_hash: accepted.head.content_hash.to_vec(),
                    size_bytes: accepted.head.size,
                },
                Err(reason) => VaultHeadCheck::Refused {
                    reason: reason.into(),
                },
            },
        )
    }

    /// The ids of the roster's devices, in ascending order of their
    /// enrolments' byte forms (not the order they were given in).
    #[must_use]
    pub fn device_ids(&self) -> Vec<Vec<u8>> {
        self.inner
            .devices()
            .iter()
            .map(|d| d.device_id().to_vec())
            .collect()
    }
}
