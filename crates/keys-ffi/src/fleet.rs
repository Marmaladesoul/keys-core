//! The account's fleet document across the FFI: the fleet key, writing a
//! record, and reading the document back as one view of the account.
//!
//! **Where the fleet key goes.** [`FleetKey::stored_form`] is readable after
//! the device's first unlock, device-only, like the device's sync keys: a
//! locked device still reads the fleet document to know which authors its
//! vault documents bind. It is a secret: don't log it.
//!
//! **Writing.** Sign the account's records with [`PairingAccountKeys`]
//! (enrolment, tombstone, vault epoch), then seal any record with
//! [`DeviceSyncKeys::seal_fleet_record`] and write the value under the
//! returned key with this device's author. Take each sequence from
//! [`crate::next_statement_sequence`] of the last one this device used in
//! the document.
//!
//! **Reading.** Join the document with nothing downloaded by default, fetch
//! every entry [`fleet_entry_to_fetch`] allows (from any author), and pass
//! them to [`read_fleet`] with the entries kept from the last read. Store
//! [`FleetReadResult::kept`] for next time: it is what stops the document
//! going back.

// uniffi exports take owned arguments.
#![allow(clippy::needless_pass_by_value)]

use std::sync::Arc;

use keys_account::DeviceEnrolment;
use keys_account::fleet::record::VAULT_ID_BYTES;
use keys_account::fleet::{
    self, DeviceInfo, DeviceName, FleetEntry, FleetRead, FleetRecord, FleetRefused, Holding,
    RecordError, SealError, Setting, Tombstone, VaultEpoch, VaultLook,
};
use keys_account::statement::FleetKind;
use keys_pairing as kp;
use zeroize::Zeroizing;

use crate::account::{
    AccountFfiError, AccountRoster, DeviceEnrolmentRecord, DeviceSyncKeys, key32,
};
use crate::pairing::PairingAccountKeys;

impl From<RecordError> for AccountFfiError {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::NotAccountSigned => Self::FleetRecordNotSignedByAccount,
            RecordError::UnusableKey => Self::EnrolmentUnusableKey,
            RecordError::Malformed | RecordError::Invalid => Self::FleetRecordInvalid,
        }
    }
}

impl From<SealError> for AccountFfiError {
    fn from(error: SealError) -> Self {
        match error {
            SealError::Record(error) => error.into(),
            SealError::Random => Self::Random,
        }
    }
}

fn vault_id(bytes: &[u8]) -> Result<[u8; VAULT_ID_BYTES], AccountFfiError> {
    bytes
        .try_into()
        .map_err(|_| AccountFfiError::InvalidVaultIdLength)
}

/// The largest colour, `0xRRGGBB`.
const MAX_COLOUR_RGB: u32 = 0x00ff_ffff;

// ─── the fleet key ──────────────────────────────────────────────────────────

/// An account's fleet key: seals every value in its fleet document and
/// names the entries.
#[derive(uniffi::Object)]
pub struct FleetKey {
    inner: kp::FleetKey,
}

#[uniffi::export]
impl FleetKey {
    /// A fresh fleet key, for a new account's fleet document.
    ///
    /// # Errors
    /// [`AccountFfiError::Random`] if the system random source fails.
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, AccountFfiError> {
        Ok(Arc::new(Self {
            inner: kp::FleetKey::generate().map_err(|_| AccountFfiError::Random)?,
        }))
    }

    /// Reads the stored form back.
    ///
    /// # Errors
    /// [`AccountFfiError::StoredKeysWrongKind`] or
    /// [`AccountFfiError::StoredKeysDamaged`].
    #[uniffi::constructor]
    pub fn from_stored(stored: Vec<u8>) -> Result<Arc<Self>, AccountFfiError> {
        let stored = Zeroizing::new(stored);
        Ok(Arc::new(Self {
            inner: kp::FleetKey::from_stored(&stored)?,
        }))
    }

    /// The stored form. A secret: don't log it.
    #[must_use]
    pub fn stored_form(&self) -> Vec<u8> {
        self.inner.to_stored().to_vec()
    }
}

// ─── the account's records ──────────────────────────────────────────────────

#[uniffi::export]
impl PairingAccountKeys {
    /// The account's tombstone for the device `device_id`: its removal,
    /// which outranks every enrolment of it. Seal it as
    /// [`FleetRecordInput::Tombstone`].
    ///
    /// # Errors
    /// [`AccountFfiError::InvalidKeyLength`] if `device_id` isn't 32 bytes,
    /// [`AccountFfiError::FleetRecordInvalid`] if it isn't a usable Ed25519
    /// key, so isn't any device's id.
    pub fn sign_device_tombstone(&self, device_id: Vec<u8>) -> Result<Vec<u8>, AccountFfiError> {
        Ok(FleetRecord::Tombstone(Tombstone::sign(&self.inner, &key32(&device_id)?)?).encode()?)
    }

    /// The account's statement that epoch `epoch` of the vault `vault_id`
    /// syncs through document `doc_id`. Seal it as
    /// [`FleetRecordInput::VaultEpoch`].
    ///
    /// # Errors
    /// [`AccountFfiError::InvalidVaultIdLength`] or
    /// [`AccountFfiError::InvalidKeyLength`].
    pub fn sign_vault_epoch(
        &self,
        vault_id: Vec<u8>,
        doc_id: Vec<u8>,
        epoch: u64,
    ) -> Result<Vec<u8>, AccountFfiError> {
        let id = self::vault_id(&vault_id)?;
        Ok(
            FleetRecord::VaultEpoch(VaultEpoch::sign(&self.inner, &id, &key32(&doc_id)?, epoch))
                .encode()?,
        )
    }
}

// ─── writing ────────────────────────────────────────────────────────────────

/// A peer's latest head, in a holding statement.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PeerHead {
    pub device_id: Vec<u8>,
    pub head_hash: Vec<u8>,
}

/// A record to write into the fleet document.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum FleetRecordInput {
    /// A device's enrolment, as [`PairingAccountKeys::enrol_device`] made
    /// it. Any device may write any enrolment.
    Enrolment { enrolment: Vec<u8> },
    /// From [`PairingAccountKeys::sign_device_tombstone`].
    Tombstone { tombstone: Vec<u8> },
    /// From [`PairingAccountKeys::sign_vault_epoch`].
    VaultEpoch { vault_epoch: Vec<u8> },
    /// What this device says about itself. Times in microseconds since the
    /// Unix epoch; `platform` a lower-case identifier such as `macos`.
    DeviceInfo {
        platform: String,
        paired_at: u64,
        last_seen: u64,
    },
    /// A device's name, which any device may set. Sanitised for display
    /// first; refused if nothing visible is left.
    DeviceName { device_id: Vec<u8>, name: String },
    /// How a vault looks. `icon` a lower-case identifier, `colour_rgb`
    /// `0xRRGGBB`, `name` sanitised as for a device's.
    VaultLook {
        vault_id: Vec<u8>,
        name: String,
        icon: String,
        colour_rgb: u32,
    },
    /// Which epoch of a vault this device holds, and the copies it has.
    Holding {
        vault_id: Vec<u8>,
        epoch: u64,
        has_secrets: bool,
        own_head: Option<Vec<u8>>,
        peer_heads: Vec<PeerHead>,
    },
    /// One of the account's settings: a lower-case identifier and a value.
    Setting { name: String, value: Vec<u8> },
}

/// A sealed record: write `value` under `key`, with this device's author.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct SealedFleetEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl FleetRecordInput {
    /// The record, with the account's records checked against `identity`.
    fn into_record(self, identity: &[u8; 32]) -> Result<FleetRecord, AccountFfiError> {
        let record = match self {
            Self::Enrolment { enrolment } => {
                FleetRecord::Enrolment(DeviceEnrolment::open(&enrolment, identity)?)
            }
            Self::Tombstone { tombstone } => {
                FleetRecord::decode(FleetKind::Tombstone, &tombstone, identity)?
            }
            Self::VaultEpoch { vault_epoch } => {
                FleetRecord::decode(FleetKind::VaultEpoch, &vault_epoch, identity)?
            }
            Self::DeviceInfo {
                platform,
                paired_at,
                last_seen,
            } => FleetRecord::DeviceInfo(DeviceInfo {
                platform,
                paired_at,
                last_seen,
            }),
            Self::DeviceName { device_id, name } => FleetRecord::DeviceName(DeviceName {
                device_id: key32(&device_id)?,
                name: kp::sanitize_display_name(&name),
            }),
            Self::VaultLook {
                vault_id,
                name,
                icon,
                colour_rgb,
            } => {
                if colour_rgb > MAX_COLOUR_RGB {
                    return Err(AccountFfiError::FleetRecordInvalid);
                }
                let [_, red, green, blue] = colour_rgb.to_be_bytes();
                FleetRecord::VaultLook(VaultLook {
                    vault_id: self::vault_id(&vault_id)?,
                    name: kp::sanitize_display_name(&name),
                    icon,
                    colour: [red, green, blue],
                })
            }
            Self::Holding {
                vault_id,
                epoch,
                has_secrets,
                own_head,
                peer_heads,
            } => {
                let mut peers = peer_heads
                    .iter()
                    .map(|peer| Ok((key32(&peer.device_id)?, key32(&peer.head_hash)?)))
                    .collect::<Result<Vec<_>, AccountFfiError>>()?;
                peers.sort_unstable();
                FleetRecord::Holding(Holding {
                    vault_id: self::vault_id(&vault_id)?,
                    epoch,
                    has_secrets,
                    own_head: own_head.as_deref().map(key32).transpose()?,
                    peer_heads: peers,
                })
            }
            Self::Setting { name, value } => FleetRecord::Setting(Setting { name, value }),
        };
        Ok(record)
    }
}

#[uniffi::export]
impl DeviceSyncKeys {
    /// Signs `record` with this device's signing key at `sequence` and seals
    /// it under `fleet_key` for document `doc_id` of the account whose
    /// identity key is `account_identity`.
    ///
    /// # Errors
    /// [`AccountFfiError::InvalidKeyLength`] or
    /// [`AccountFfiError::InvalidVaultIdLength`] for an id of the wrong
    /// length; [`AccountFfiError::FleetRecordInvalid`] for a record that
    /// can't be written as given; an enrolment's own refusal, or
    /// [`AccountFfiError::FleetRecordNotSignedByAccount`], for an account
    /// record that isn't this account's; [`AccountFfiError::Random`].
    pub fn seal_fleet_record(
        &self,
        fleet_key: Arc<FleetKey>,
        account_identity: Vec<u8>,
        doc_id: Vec<u8>,
        sequence: u64,
        record: FleetRecordInput,
    ) -> Result<SealedFleetEntry, AccountFfiError> {
        let record = record.into_record(&key32(&account_identity)?)?;
        let sealed = fleet::seal_record(
            &fleet_key.inner,
            &key32(&doc_id)?,
            &self.inner,
            sequence,
            &record,
        )?;
        Ok(SealedFleetEntry {
            key: sealed.key.to_vec(),
            value: sealed.value,
        })
    }
}

/// Whether to fetch an entry of the fleet document whose recorded size is
/// `size_bytes`: anything small enough to be a record, from any author.
#[uniffi::export]
#[must_use]
pub fn fleet_entry_to_fetch(size_bytes: u64) -> bool {
    fleet::fleet_entry_to_fetch(size_bytes)
}

/// The largest fleet entry: the cap for each fetch.
#[uniffi::export]
#[must_use]
pub fn fleet_entry_max_bytes() -> u64 {
    fleet::MAX_SEALED_BYTES as u64
}

/// Whether to write this device's last-seen time again, if it was last
/// written at `last_written` (microseconds, this device's clock).
#[uniffi::export]
#[must_use]
pub fn fleet_last_seen_due(last_written: Option<u64>, now_micros: u64) -> bool {
    fleet::last_seen_due(last_written, now_micros)
}

// ─── reading ────────────────────────────────────────────────────────────────

/// An entry of the fleet document, as the document layer gives it, or as
/// kept from the last read.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FleetEntryRecord {
    pub author: Vec<u8>,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// What a device last said about itself.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FleetDeviceInfo {
    pub platform: String,
    pub paired_at: u64,
    pub last_seen: u64,
}

/// A current device of the account.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FleetDeviceRecord {
    pub enrolment: DeviceEnrolmentRecord,
    pub name: Option<String>,
    pub info: Option<FleetDeviceInfo>,
}

/// How a vault looks.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FleetVaultLook {
    pub name: String,
    pub icon: String,
    /// `0xRRGGBB`.
    pub colour_rgb: u32,
}

/// What a device holds of a vault: that device's claim, so `epoch` may
/// differ from the vault's. `peer_heads` lists only current devices.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FleetHoldingRecord {
    pub device_id: Vec<u8>,
    pub epoch: u64,
    pub has_secrets: bool,
    pub own_head: Option<Vec<u8>>,
    pub peer_heads: Vec<PeerHead>,
}

/// A vault in the account's index.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FleetVaultRecord {
    pub vault_id: Vec<u8>,
    pub epoch: u64,
    /// The document the vault syncs through at that epoch. Not public: keep
    /// it out of logs.
    pub doc_id: Vec<u8>,
    pub look: Option<FleetVaultLook>,
    pub holdings: Vec<FleetHoldingRecord>,
}

/// One of the account's settings.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FleetSettingRecord {
    pub name: String,
    pub value: Vec<u8>,
}

/// Why an entry of the fleet document doesn't count.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetRefusal {
    /// Longer than any fleet record.
    TooLarge,
    /// Doesn't open under the fleet key for this document and entry: a
    /// stranger's, damaged, or moved.
    NotSealed,
    /// Opens, but isn't a statement signed for this entry by a usable key.
    NotSigned,
    /// A statement, but not a fleet record.
    NotAFleetRecord,
    /// Not a record's canonical byte form.
    Malformed,
    /// An account record not signed by the account.
    NotSignedByAccount,
    /// An enrolment signed by the account that names a key it can't use.
    UnusableKey,
    /// An entry whose author isn't 32 bytes.
    NotAnAuthor,
    /// Not in its own slot's entry.
    Misplaced,
    /// An enrolment that clashes with another; both are refused.
    Clashing,
    /// The enrolment of a removed device, or a removed device's word.
    Removed,
    /// A device's word not written by a current device under its own
    /// author.
    Unbound,
    /// A holding statement that lists its own device as a peer.
    SelfPeer,
}

impl From<FleetRefused> for FleetRefusal {
    fn from(reason: FleetRefused) -> Self {
        match reason {
            FleetRefused::TooLarge => Self::TooLarge,
            FleetRefused::NotSealed => Self::NotSealed,
            FleetRefused::Statement(_) => Self::NotSigned,
            FleetRefused::NotAFleetRecord => Self::NotAFleetRecord,
            FleetRefused::Record(RecordError::Malformed | RecordError::Invalid) => Self::Malformed,
            FleetRefused::Record(RecordError::NotAccountSigned) => Self::NotSignedByAccount,
            FleetRefused::Record(RecordError::UnusableKey) => Self::UnusableKey,
            FleetRefused::Misplaced => Self::Misplaced,
            FleetRefused::Clashing => Self::Clashing,
            FleetRefused::Removed => Self::Removed,
            FleetRefused::Unbound => Self::Unbound,
            FleetRefused::SelfPeer => Self::SelfPeer,
        }
    }
}

/// An entry that doesn't count, and why.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FleetRefusalRecord {
    pub author: Vec<u8>,
    pub key: Vec<u8>,
    pub reason: FleetRefusal,
}

/// The account, as its fleet document has it.
#[derive(uniffi::Record)]
pub struct FleetReadResult {
    /// Current devices, ascending by device id.
    pub devices: Vec<FleetDeviceRecord>,
    /// Removed devices' ids.
    pub removed: Vec<Vec<u8>>,
    /// Vaults with an epoch, ascending by vault id.
    pub vaults: Vec<FleetVaultRecord>,
    pub settings: Vec<FleetSettingRecord>,
    /// The current devices as a roster, for vault documents' heads.
    pub roster: Arc<AccountRoster>,
    /// Store these, and pass them back in with the next read.
    pub kept: Vec<FleetEntryRecord>,
    pub refused: Vec<FleetRefusalRecord>,
}

/// Reads fleet document `doc_id` of the account whose identity key is
/// `account_identity`, from `entries`: what was fetched, and what was kept
/// from the last read.
///
/// One entry's failure is that entry's: an entry whose author isn't 32
/// bytes is refused ([`FleetRefusal::NotAnAuthor`]) and the rest are read.
///
/// # Errors
/// [`AccountFfiError::InvalidKeyLength`] if `account_identity` or `doc_id`
/// isn't 32 bytes.
#[uniffi::export]
pub fn read_fleet(
    account_identity: Vec<u8>,
    fleet_key: Arc<FleetKey>,
    doc_id: Vec<u8>,
    entries: Vec<FleetEntryRecord>,
) -> Result<FleetReadResult, AccountFfiError> {
    let identity = key32(&account_identity)?;
    let doc_id = key32(&doc_id)?;
    let mut not_authors = Vec::new();
    let mut readable = Vec::with_capacity(entries.len());
    for entry in entries {
        match <[u8; 32]>::try_from(entry.author.as_slice()) {
            Ok(author) => readable.push(FleetEntry {
                author,
                key: entry.key,
                value: entry.value,
            }),
            Err(_) => not_authors.push(FleetRefusalRecord {
                author: entry.author,
                key: entry.key,
                reason: FleetRefusal::NotAnAuthor,
            }),
        }
    }
    let mut result = FleetReadResult::from(fleet::read_fleet(
        &identity,
        &fleet_key.inner,
        &doc_id,
        readable,
    ));
    result.refused.extend(not_authors);
    Ok(result)
}

impl From<FleetRead> for FleetReadResult {
    fn from(fleet_read: FleetRead) -> Self {
        let view = fleet_read.view;
        Self {
            devices: view
                .devices
                .iter()
                .map(|device| FleetDeviceRecord {
                    enrolment: (&device.enrolment).into(),
                    name: device.name.clone(),
                    info: device.info.as_ref().map(|info| FleetDeviceInfo {
                        platform: info.platform.clone(),
                        paired_at: info.paired_at,
                        last_seen: info.last_seen,
                    }),
                })
                .collect(),
            removed: view.removed.iter().map(|id| id.to_vec()).collect(),
            vaults: view
                .vaults
                .iter()
                .map(|vault| FleetVaultRecord {
                    vault_id: vault.vault_id.to_vec(),
                    epoch: vault.epoch,
                    doc_id: vault.doc_id.to_vec(),
                    look: vault.look.as_ref().map(|look| {
                        let [red, green, blue] = look.colour;
                        FleetVaultLook {
                            name: look.name.clone(),
                            icon: look.icon.clone(),
                            colour_rgb: u32::from_be_bytes([0, red, green, blue]),
                        }
                    }),
                    holdings: vault
                        .holdings
                        .iter()
                        .map(|(device, holding)| FleetHoldingRecord {
                            device_id: device.to_vec(),
                            epoch: holding.epoch,
                            has_secrets: holding.has_secrets,
                            own_head: holding.own_head.map(|head| head.to_vec()),
                            peer_heads: holding
                                .peer_heads
                                .iter()
                                .map(|(peer, head)| PeerHead {
                                    device_id: peer.to_vec(),
                                    head_hash: head.to_vec(),
                                })
                                .collect(),
                        })
                        .collect(),
                })
                .collect(),
            settings: view
                .settings
                .iter()
                .map(|setting| FleetSettingRecord {
                    name: setting.name.clone(),
                    value: setting.value.clone(),
                })
                .collect(),
            roster: AccountRoster::from_roster(view.roster),
            kept: fleet_read
                .kept
                .into_iter()
                .map(|entry| FleetEntryRecord {
                    author: entry.author.to_vec(),
                    key: entry.key,
                    value: entry.value,
                })
                .collect(),
            refused: fleet_read
                .refused
                .into_iter()
                .map(|refusal| FleetRefusalRecord {
                    author: refusal.author.to_vec(),
                    key: refusal.key,
                    reason: refusal.reason.into(),
                })
                .collect(),
        }
    }
}
