//! The fleet document's records and their byte forms.
//!
//! Each record is a statement's payload ([`crate::statement`]). Three are
//! made by the account identity key and count on that signature alone,
//! whoever writes them: an enrolment, a tombstone and a vault epoch. The
//! rest are a device's own word and count only from a current device under
//! its own author ([`super::read`]).
//!
//! Every record has a **slot**, what it is about: its kind and its subject
//! (a device id, a vault id, a setting's name, or nothing for what a device
//! says about itself). The slot names the entry the record is written
//! under, so one writer has one record per slot, and the reader checks that
//! a record sits in its own slot.
//!
//! Byte forms are fixed fields in order, then variable fields each with a
//! two-byte big-endian length. A form is read in one canonical way only:
//! names exactly as [`sanitize_display_name`] leaves them, identifiers in
//! lower-case ASCII, peers in ascending order, no unknown flags, nothing
//! left over. So two readers given the same bytes read the same record, and
//! a writer can't make one record that readers read two ways.

use keys_pairing::address::MAX_DISPLAY_NAME_BYTES;
use keys_pairing::keys::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES, ed25519_public_key_is_usable};
use keys_pairing::{AccountKeys, SignedStatement, sanitize_display_name};

use crate::enrolment::{DeviceEnrolment, ENROLMENT_BYTES, EnrolmentError};
use crate::statement::{DOC_ID_BYTES, FleetKind, MAX_PAYLOAD_BYTES, StatementKind};
use crate::vault_head::CONTENT_HASH_BYTES;

/// A device's id in the account: its signing public key.
pub type DeviceId = [u8; PUBLIC_KEY_BYTES];
/// Length of a vault id (a UUID).
pub const VAULT_ID_BYTES: usize = 16;
/// A vault's id.
pub type VaultId = [u8; VAULT_ID_BYTES];
/// A head's hash ([`crate::vault_head`]).
pub type HeadHash = [u8; CONTENT_HASH_BYTES];

/// The most peers a holding statement lists.
pub const MAX_PEER_HEADS: usize = 15;
/// The longest platform identifier.
pub const MAX_PLATFORM_BYTES: usize = 16;
/// The longest icon identifier.
pub const MAX_ICON_BYTES: usize = 64;
/// The longest setting name.
pub const MAX_SETTING_NAME_BYTES: usize = 64;
/// The longest setting value.
pub const MAX_SETTING_VALUE_BYTES: usize = 256;
/// The version of the fields the account identity key signs in a record.
const ACCOUNT_FIELDS_VERSION: u8 = 1;
/// Holding flags.
const HOLDS_SECRETS: u8 = 1;
const HAS_OWN_HEAD: u8 = 2;
/// A variable field's length prefix.
const LENGTH_BYTES: usize = 2;
const EPOCH_BYTES: usize = 8;
const COLOUR_BYTES: usize = 3;

// Every record's longest byte form fits in a statement.
const _: () = assert!(
    VAULT_ID_BYTES + COLOUR_BYTES + 2 * LENGTH_BYTES + MAX_ICON_BYTES + MAX_DISPLAY_NAME_BYTES
        <= MAX_PAYLOAD_BYTES
);
const _: () = assert!(
    VAULT_ID_BYTES
        + EPOCH_BYTES
        + 1
        + CONTENT_HASH_BYTES
        + 1
        + MAX_PEER_HEADS * (PUBLIC_KEY_BYTES + CONTENT_HASH_BYTES)
        <= MAX_PAYLOAD_BYTES
);
const _: () = assert!(
    2 * LENGTH_BYTES + MAX_SETTING_NAME_BYTES + MAX_SETTING_VALUE_BYTES <= MAX_PAYLOAD_BYTES
);
const _: () = assert!(ENROLMENT_BYTES <= MAX_PAYLOAD_BYTES);
const _: () = assert!(MAX_PEER_HEADS <= u8::MAX as usize);

/// Why a record was refused, or couldn't be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// Not the record's byte form, or not its one canonical form.
    #[error("not a fleet record")]
    Malformed,
    /// A record the account identity key makes, not signed by it.
    #[error("not signed by the account")]
    NotAccountSigned,
    /// An enrolment the account refuses ([`EnrolmentError`]).
    #[error("not an enrolment of this account")]
    NotEnrolled,
    /// A name with nothing visible in it, an identifier that isn't
    /// lower-case ASCII, or a field over its limit: nothing is written.
    #[error("the record can't be written as given")]
    Invalid,
}

/// A device's removal from the account. Made by the account identity key; it
/// outranks every enrolment of the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tombstone {
    device_id: DeviceId,
    signature: [u8; SIGNATURE_BYTES],
}

impl Tombstone {
    /// The account's tombstone for `device_id`.
    ///
    /// # Errors
    /// [`RecordError::Invalid`] if `device_id` isn't a usable Ed25519 key
    /// ([`ed25519_public_key_is_usable`]), so isn't any device's id: a
    /// tombstone for it would remove nobody.
    pub fn sign(account: &AccountKeys, device_id: &DeviceId) -> Result<Self, RecordError> {
        if !ed25519_public_key_is_usable(device_id) {
            return Err(RecordError::Invalid);
        }
        Ok(Self {
            device_id: *device_id,
            signature: account.sign_statement(
                SignedStatement::DeviceTombstone,
                &tombstone_fields(device_id),
            ),
        })
    }

    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    fn verify(&self, identity: &[u8; PUBLIC_KEY_BYTES]) -> bool {
        SignedStatement::DeviceTombstone.verify(
            identity,
            &tombstone_fields(&self.device_id),
            &self.signature,
        )
    }
}

fn tombstone_fields(device_id: &DeviceId) -> [&[u8]; 2] {
    [&[ACCOUNT_FIELDS_VERSION], device_id]
}

/// A vault's epoch: which document it syncs through from that epoch on.
/// Made by the account identity key, so only a re-key (a user-present act)
/// moves a vault to a new document, and only forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultEpoch {
    vault_id: VaultId,
    doc_id: [u8; DOC_ID_BYTES],
    epoch: u64,
    signature: [u8; SIGNATURE_BYTES],
}

impl VaultEpoch {
    /// The account's statement that `vault_id`'s epoch `epoch` syncs through
    /// document `doc_id`.
    #[must_use]
    pub fn sign(
        account: &AccountKeys,
        vault_id: &VaultId,
        doc_id: &[u8; DOC_ID_BYTES],
        epoch: u64,
    ) -> Self {
        let signature = with_epoch_fields(vault_id, doc_id, epoch, |fields| {
            account.sign_statement(SignedStatement::VaultEpoch, fields)
        });
        Self {
            vault_id: *vault_id,
            doc_id: *doc_id,
            epoch,
            signature,
        }
    }

    #[must_use]
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    #[must_use]
    pub fn doc_id(&self) -> [u8; DOC_ID_BYTES] {
        self.doc_id
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn verify(&self, identity: &[u8; PUBLIC_KEY_BYTES]) -> bool {
        with_epoch_fields(&self.vault_id, &self.doc_id, self.epoch, |fields| {
            SignedStatement::VaultEpoch.verify(identity, fields, &self.signature)
        })
    }
}

fn with_epoch_fields<R>(
    vault_id: &VaultId,
    doc_id: &[u8; DOC_ID_BYTES],
    epoch: u64,
    f: impl FnOnce(&[&[u8]]) -> R,
) -> R {
    f(&[
        &[ACCOUNT_FIELDS_VERSION],
        vault_id,
        doc_id,
        &epoch.to_be_bytes(),
    ])
}

/// What a device says about itself. Times are microseconds since the Unix
/// epoch, by the device's own clock, for display only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// A lower-case identifier such as `macos`.
    pub platform: String,
    pub paired_at: u64,
    /// Rewritten at most hourly ([`super::LAST_SEEN_INTERVAL_MICROS`]).
    pub last_seen: u64,
}

/// A device's name: one name for it on every device of the account. Any
/// device may set it; the latest wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceName {
    pub device_id: DeviceId,
    pub name: String,
}

/// How a vault looks on every device of the account, including devices that
/// don't hold it. Any device may set it; the latest wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultLook {
    pub vault_id: VaultId,
    pub name: String,
    /// A lower-case identifier for the icon.
    pub icon: String,
    /// Red, green, blue.
    pub colour: [u8; COLOUR_BYTES],
}

/// Which epoch of a vault a device holds, and the copies it has. Written by
/// the device itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holding {
    pub vault_id: VaultId,
    pub epoch: u64,
    /// Whether it holds that epoch's secrets, or so far only relays its
    /// encrypted copies.
    pub has_secrets: bool,
    /// The hash of the head of its own copy, once it has published one.
    pub own_head: Option<HeadHash>,
    /// The latest head it has from each peer, in ascending order of device
    /// id, at most [`MAX_PEER_HEADS`], never itself.
    pub peer_heads: Vec<(DeviceId, HeadHash)>,
}

/// One of the account's settings: a value that follows the user to every
/// device. Any device may set it; the latest wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// A lower-case identifier.
    pub name: String,
    pub value: Vec<u8>,
}

/// A fleet document record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetRecord {
    Enrolment(DeviceEnrolment),
    Tombstone(Tombstone),
    VaultEpoch(VaultEpoch),
    DeviceInfo(DeviceInfo),
    DeviceName(DeviceName),
    VaultLook(VaultLook),
    Holding(Holding),
    Setting(Setting),
}

impl FleetRecord {
    #[must_use]
    pub fn kind(&self) -> FleetKind {
        match self {
            Self::Enrolment(_) => FleetKind::Enrolment,
            Self::Tombstone(_) => FleetKind::Tombstone,
            Self::VaultEpoch(_) => FleetKind::VaultEpoch,
            Self::DeviceInfo(_) => FleetKind::DeviceInfo,
            Self::DeviceName(_) => FleetKind::DeviceName,
            Self::VaultLook(_) => FleetKind::VaultLook,
            Self::Holding(_) => FleetKind::Holding,
            Self::Setting(_) => FleetKind::Setting,
        }
    }

    /// Whether the account identity key makes this record, so it counts on
    /// that signature alone, whoever writes it.
    #[must_use]
    pub fn is_the_accounts(&self) -> bool {
        matches!(
            self,
            Self::Enrolment(_) | Self::Tombstone(_) | Self::VaultEpoch(_)
        )
    }

    /// What the record is about: its kind's wire byte and its subject.
    pub(crate) fn slot(&self) -> Vec<u8> {
        let mut slot = vec![StatementKind::Fleet(self.kind()).wire()];
        match self {
            Self::Enrolment(enrolment) => slot.extend_from_slice(&enrolment.device_id()),
            Self::Tombstone(tombstone) => slot.extend_from_slice(&tombstone.device_id),
            Self::VaultEpoch(epoch) => slot.extend_from_slice(&epoch.vault_id),
            Self::DeviceInfo(_) => {}
            Self::DeviceName(name) => slot.extend_from_slice(&name.device_id),
            Self::VaultLook(look) => slot.extend_from_slice(&look.vault_id),
            Self::Holding(holding) => slot.extend_from_slice(&holding.vault_id),
            Self::Setting(setting) => slot.extend_from_slice(setting.name.as_bytes()),
        }
        slot
    }

    /// The byte form.
    ///
    /// # Errors
    /// [`RecordError::Invalid`] if a field isn't in its canonical form or is
    /// over its limit. Names are written as [`sanitize_display_name`] leaves
    /// them, so pass a name through it first.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::new();
        match self {
            Self::Enrolment(enrolment) => out.extend_from_slice(&enrolment.to_bytes()),
            Self::Tombstone(tombstone) => {
                out.extend_from_slice(&tombstone.device_id);
                out.extend_from_slice(&tombstone.signature);
            }
            Self::VaultEpoch(epoch) => {
                out.extend_from_slice(&epoch.vault_id);
                out.extend_from_slice(&epoch.doc_id);
                out.extend_from_slice(&epoch.epoch.to_be_bytes());
                out.extend_from_slice(&epoch.signature);
            }
            Self::DeviceInfo(info) => {
                out.extend_from_slice(&info.paired_at.to_be_bytes());
                out.extend_from_slice(&info.last_seen.to_be_bytes());
                push_field(&mut out, identifier(&info.platform, MAX_PLATFORM_BYTES)?);
            }
            Self::DeviceName(name) => {
                out.extend_from_slice(&name.device_id);
                push_field(&mut out, display_name(&name.name)?);
            }
            Self::VaultLook(look) => {
                out.extend_from_slice(&look.vault_id);
                out.extend_from_slice(&look.colour);
                push_field(&mut out, identifier(&look.icon, MAX_ICON_BYTES)?);
                push_field(&mut out, display_name(&look.name)?);
            }
            Self::Holding(holding) => encode_holding(&mut out, holding)?,
            Self::Setting(setting) => {
                push_field(&mut out, identifier(&setting.name, MAX_SETTING_NAME_BYTES)?);
                if setting.value.len() > MAX_SETTING_VALUE_BYTES {
                    return Err(RecordError::Invalid);
                }
                push_field(&mut out, &setting.value);
            }
        }
        debug_assert!(out.len() <= MAX_PAYLOAD_BYTES);
        Ok(out)
    }

    /// Reads a record of `kind` from `payload`, checking the account
    /// identity key's signature on the records it makes.
    ///
    /// # Errors
    /// [`RecordError`] if it isn't the record's canonical byte form, or an
    /// account record isn't signed by `identity`.
    pub fn decode(
        kind: FleetKind,
        payload: &[u8],
        identity: &[u8; PUBLIC_KEY_BYTES],
    ) -> Result<Self, RecordError> {
        let mut reader = Reader(payload);
        let record = match kind {
            FleetKind::Enrolment => {
                let enrolment = DeviceEnrolment::open(reader.rest(), identity).map_err(
                    |error| match error {
                        EnrolmentError::Malformed => RecordError::Malformed,
                        _ => RecordError::NotEnrolled,
                    },
                )?;
                Self::Enrolment(enrolment)
            }
            FleetKind::Tombstone => {
                let tombstone = Tombstone {
                    device_id: reader.array()?,
                    signature: reader.array()?,
                };
                reader.finish()?;
                if !ed25519_public_key_is_usable(&tombstone.device_id) {
                    return Err(RecordError::Malformed);
                }
                if !tombstone.verify(identity) {
                    return Err(RecordError::NotAccountSigned);
                }
                Self::Tombstone(tombstone)
            }
            FleetKind::VaultEpoch => {
                let epoch = VaultEpoch {
                    vault_id: reader.array()?,
                    doc_id: reader.array()?,
                    epoch: reader.u64()?,
                    signature: reader.array()?,
                };
                reader.finish()?;
                if !epoch.verify(identity) {
                    return Err(RecordError::NotAccountSigned);
                }
                Self::VaultEpoch(epoch)
            }
            FleetKind::DeviceInfo => {
                let paired_at = reader.u64()?;
                let last_seen = reader.u64()?;
                let platform = reader.identifier(MAX_PLATFORM_BYTES)?;
                reader.finish()?;
                Self::DeviceInfo(DeviceInfo {
                    platform,
                    paired_at,
                    last_seen,
                })
            }
            FleetKind::DeviceName => {
                let device_id = reader.array()?;
                let name = reader.display_name()?;
                reader.finish()?;
                Self::DeviceName(DeviceName { device_id, name })
            }
            FleetKind::VaultLook => {
                let vault_id = reader.array()?;
                let colour = reader.array()?;
                let icon = reader.identifier(MAX_ICON_BYTES)?;
                let name = reader.display_name()?;
                reader.finish()?;
                Self::VaultLook(VaultLook {
                    vault_id,
                    name,
                    icon,
                    colour,
                })
            }
            FleetKind::Holding => {
                let holding = decode_holding(&mut reader)?;
                reader.finish()?;
                Self::Holding(holding)
            }
            FleetKind::Setting => {
                let name = reader.identifier(MAX_SETTING_NAME_BYTES)?;
                let value = reader.field()?;
                if value.len() > MAX_SETTING_VALUE_BYTES {
                    return Err(RecordError::Malformed);
                }
                reader.finish()?;
                Self::Setting(Setting {
                    name,
                    value: value.to_vec(),
                })
            }
        };
        Ok(record)
    }
}

fn encode_holding(out: &mut Vec<u8>, holding: &Holding) -> Result<(), RecordError> {
    if !peers_are_canonical(&holding.peer_heads) {
        return Err(RecordError::Invalid);
    }
    out.extend_from_slice(&holding.vault_id);
    out.extend_from_slice(&holding.epoch.to_be_bytes());
    let mut flags = 0;
    if holding.has_secrets {
        flags |= HOLDS_SECRETS;
    }
    if holding.own_head.is_some() {
        flags |= HAS_OWN_HEAD;
    }
    out.push(flags);
    if let Some(head) = &holding.own_head {
        out.extend_from_slice(head);
    }
    out.push(u8::try_from(holding.peer_heads.len()).map_err(|_| RecordError::Invalid)?);
    for (device, head) in &holding.peer_heads {
        out.extend_from_slice(device);
        out.extend_from_slice(head);
    }
    Ok(())
}

fn decode_holding(reader: &mut Reader<'_>) -> Result<Holding, RecordError> {
    let vault_id = reader.array()?;
    let epoch = reader.u64()?;
    let [flags] = reader.array()?;
    if flags & !(HOLDS_SECRETS | HAS_OWN_HEAD) != 0 {
        return Err(RecordError::Malformed);
    }
    let own_head = if flags & HAS_OWN_HEAD == 0 {
        None
    } else {
        Some(reader.array()?)
    };
    let [count] = reader.array()?;
    let mut peer_heads = Vec::with_capacity(usize::from(count).min(MAX_PEER_HEADS));
    for _ in 0..count {
        peer_heads.push((reader.array()?, reader.array()?));
    }
    if !peers_are_canonical(&peer_heads) {
        return Err(RecordError::Malformed);
    }
    Ok(Holding {
        vault_id,
        epoch,
        has_secrets: flags & HOLDS_SECRETS != 0,
        own_head,
        peer_heads,
    })
}

/// At most [`MAX_PEER_HEADS`], each a usable Ed25519 key (so one device has
/// one id here, never a second spelling of it), in strictly ascending order
/// of device id. (That the signer isn't among them is the reader's to check:
/// the record doesn't know who signs it.)
fn peers_are_canonical(peers: &[(DeviceId, HeadHash)]) -> bool {
    peers.len() <= MAX_PEER_HEADS
        && peers
            .iter()
            .all(|(peer, _)| ed25519_public_key_is_usable(peer))
        && peers.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

/// `name` if it is a name as [`sanitize_display_name`] leaves it, and not
/// empty.
fn display_name(name: &str) -> Result<&[u8], RecordError> {
    if name.is_empty() || sanitize_display_name(name) != name {
        return Err(RecordError::Invalid);
    }
    debug_assert!(name.len() <= MAX_DISPLAY_NAME_BYTES);
    Ok(name.as_bytes())
}

/// `text` if it is a non-empty identifier of lower-case ASCII letters,
/// digits, `.`, `_` and `-`, at most `max` bytes.
fn identifier(text: &str, max: usize) -> Result<&[u8], RecordError> {
    let fits = !text.is_empty()
        && text.len() <= max
        && text
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if fits {
        Ok(text.as_bytes())
    } else {
        Err(RecordError::Invalid)
    }
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    let length = u16::try_from(field.len()).expect("fields are capped far below 64 KiB");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(field);
}

/// Reads a byte form front to back.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], RecordError> {
        let (&array, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(RecordError::Malformed)?;
        self.0 = rest;
        Ok(array)
    }

    fn u64(&mut self) -> Result<u64, RecordError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn field(&mut self) -> Result<&'a [u8], RecordError> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        let (field, rest) = self
            .0
            .split_at_checked(length)
            .ok_or(RecordError::Malformed)?;
        self.0 = rest;
        Ok(field)
    }

    fn text(&mut self) -> Result<&'a str, RecordError> {
        std::str::from_utf8(self.field()?).map_err(|_| RecordError::Malformed)
    }

    fn display_name(&mut self) -> Result<String, RecordError> {
        let name = self.text()?;
        display_name(name).map_err(|_| RecordError::Malformed)?;
        Ok(name.to_owned())
    }

    fn identifier(&mut self, max: usize) -> Result<String, RecordError> {
        let text = self.text()?;
        identifier(text, max).map_err(|_| RecordError::Malformed)?;
        Ok(text.to_owned())
    }

    /// Everything left, which the caller reads whole.
    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }

    fn finish(&self) -> Result<(), RecordError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(RecordError::Malformed)
        }
    }
}
