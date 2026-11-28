//! Reading the fleet document: from its entries to what the account looks
//! like.
//!
//! A reader passes [`read_fleet`] every entry it fetched, together with the
//! entries it kept from its last read ([`FleetRead::kept`]), and stores what
//! comes back as kept for next time. Keeping them is what stops the document
//! going back: an entry overwritten with an older one, or a vault's epoch
//! record overwritten with an older epoch's, changes nothing for a reader
//! that already has the newer.
//!
//! An entry counts when all of these hold:
//! - it opens under the fleet key, for this document and its own entry key;
//! - inside is a fleet record statement, signed for this document and entry
//!   key, and a record in its canonical form, in its own slot;
//! - if the account identity key makes it (an enrolment, a tombstone, a
//!   vault epoch), that signature verifies; it then counts whoever wrote it,
//!   since the account's signature is what makes it, and a device can copy
//!   it;
//! - otherwise, its signer is a current device (enrolled, not removed) and
//!   the entry sits under that device's own author.
//!
//! Then the rules:
//! - **A tombstone outranks** every enrolment of its device: a removed
//!   device is not in the roster, and nothing it signs counts.
//! - **Enrolments that clash** (two different ones sharing a device,
//!   endpoint or author id) are both refused, so an author always names one
//!   device and the roster never has to guess.
//! - **Per signer and slot, the newest statement** (highest sequence) is the
//!   one that counts. The account's own records are the exception: any copy
//!   of one carries the same record, so a reader keeps one per slot,
//!   however many signers have copied it.
//! - **An enrolment is never re-made.** Enrolments carry no sequence, so a
//!   second enrolment of a device, endpoint or author id clashes with the
//!   first for good, and anyone with the fleet key can put the first back.
//!   To re-enrol a device, remove it and enrol new keys.
//! - **Epochs only go up:** a vault is at the highest epoch any valid record
//!   gives it, and the entry carrying it is always kept.
//! - **The latest wins** where any device may set a record: a device's
//!   name, a vault's look, a setting. Latest is the highest sequence, ties
//!   going to the higher signer id, so every reader agrees.
//! - What a device says about itself (when it was last seen, what it holds)
//!   counts only from that device.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use keys_pairing::FleetKey;
use keys_pairing::fleet_key::ENTRY_KEY_BYTES;
use keys_pairing::keys::PUBLIC_KEY_BYTES;

use super::MAX_SEALED_BYTES;
use super::record::{
    DeviceId, DeviceInfo, FleetRecord, Holding, RecordError, VaultEpoch, VaultId, VaultLook,
};
use crate::enrolment::DeviceEnrolment;
use crate::statement::{DOC_ID_BYTES, Placement, Statement, StatementError, StatementKind};
use crate::vault_head::Roster;

/// An entry of the fleet document, as the document layer gives it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FleetEntry {
    pub author: [u8; PUBLIC_KEY_BYTES],
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Why an entry doesn't count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FleetRefused {
    /// Longer than any fleet value.
    #[error("too large to be a fleet record")]
    TooLarge,
    /// Doesn't open under the fleet key for this document and entry key: a
    /// stranger's, damaged, or moved from elsewhere.
    #[error("not sealed for this entry")]
    NotSealed,
    /// Opens, but isn't a device statement signed for this entry.
    #[error(transparent)]
    Statement(#[from] StatementError),
    /// A device statement, but not a fleet record.
    #[error("not a fleet record")]
    NotAFleetRecord,
    #[error(transparent)]
    Record(#[from] RecordError),
    /// A record under an entry key that isn't its slot's.
    #[error("not in its own slot")]
    Misplaced,
    /// An enrolment that clashes with another: both are refused.
    #[error("clashes with another enrolment")]
    Clashing,
    /// An enrolment of a removed device, or a statement a removed device
    /// signed.
    #[error("the device was removed")]
    Removed,
    /// A device's word, not signed by a current device of the account under
    /// its own author.
    #[error("not written by a device of this account under its own author")]
    Unbound,
    /// A holding statement that lists its own signer as a peer.
    #[error("lists itself as a peer")]
    SelfPeer,
}

/// An entry that doesn't count, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub author: [u8; PUBLIC_KEY_BYTES],
    pub key: Vec<u8>,
    pub reason: FleetRefused,
}

/// A device of the account as the fleet document has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetDevice {
    pub enrolment: DeviceEnrolment,
    /// Its name, if any device has set one.
    pub name: Option<String>,
    /// What it last said about itself.
    pub info: Option<DeviceInfo>,
}

/// A vault in the account's index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetVault {
    pub vault_id: VaultId,
    pub epoch: u64,
    /// The document the vault syncs through at that epoch.
    pub doc_id: [u8; DOC_ID_BYTES],
    pub look: Option<VaultLook>,
    /// What each current device says it holds, in ascending order of
    /// device id: its claim, so its epoch may differ from the vault's (a
    /// device behind, or ahead of what this reader has seen). Its peers are
    /// only current devices; a peer that isn't one is left out.
    pub holdings: Vec<(DeviceId, Holding)>,
}

/// One of the account's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetSetting {
    pub name: String,
    pub value: Vec<u8>,
}

/// What the account looks like.
#[derive(Debug, Clone)]
pub struct FleetView {
    /// Current devices, in ascending order of device id.
    pub devices: Vec<FleetDevice>,
    /// Removed devices' ids, ascending.
    pub removed: Vec<DeviceId>,
    /// Vaults with an epoch, in ascending order of vault id.
    pub vaults: Vec<FleetVault>,
    /// Settings, in ascending order of name.
    pub settings: Vec<FleetSetting>,
    /// The current devices as a roster, for checking vault documents.
    pub roster: Roster,
}

/// The result of a read.
#[derive(Debug, Clone)]
pub struct FleetRead {
    pub view: FleetView,
    /// The entries to keep and pass back in next time: every entry that
    /// counts, newest per signer and slot, and each vault's highest epoch.
    pub kept: Vec<FleetEntry>,
    /// Entries that don't count, and why.
    pub refused: Vec<Refusal>,
}

/// An entry that opened: its statement and record.
#[derive(Clone)]
struct Opened {
    entry: FleetEntry,
    signer: DeviceId,
    sequence: u64,
    record: FleetRecord,
}

/// Reads the fleet document `doc_id` of the account whose identity key is
/// `identity`, from `entries`: what was fetched and what was kept last time.
#[must_use]
pub fn read_fleet(
    identity: &[u8; PUBLIC_KEY_BYTES],
    fleet_key: &FleetKey,
    doc_id: &[u8; DOC_ID_BYTES],
    entries: impl IntoIterator<Item = FleetEntry>,
) -> FleetRead {
    let mut refused = Vec::new();
    let mut opened = Vec::new();
    // The same entry passed in twice (kept, and fetched again) is one entry.
    let entries: BTreeSet<FleetEntry> = entries.into_iter().collect();
    for entry in entries {
        match open(identity, fleet_key, doc_id, &entry) {
            Ok((statement, record)) => opened.push(Opened {
                entry,
                signer: statement.signer(),
                sequence: statement.sequence(),
                record,
            }),
            Err(reason) => refused.push(refusal(&entry, reason)),
        }
    }

    let removed: BTreeSet<DeviceId> = opened
        .iter()
        .filter_map(|o| match &o.record {
            FleetRecord::Tombstone(tombstone) => Some(tombstone.device_id()),
            _ => None,
        })
        .collect();
    let clashing = clashing_enrolments(&opened, &removed);
    let roster_devices: BTreeMap<DeviceId, DeviceEnrolment> = opened
        .iter()
        .filter_map(|o| match &o.record {
            FleetRecord::Enrolment(enrolment)
                if !removed.contains(&enrolment.device_id()) && !clashing.contains(enrolment) =>
            {
                Some((enrolment.device_id(), *enrolment))
            }
            _ => None,
        })
        .collect();

    // Which opened entries count.
    let mut counting = Vec::new();
    for o in opened {
        match counts(&o, &roster_devices, &removed, &clashing) {
            Ok(()) => counting.push(o),
            Err(reason) => refused.push(refusal(&o.entry, reason)),
        }
    }

    let kept_opened = kept_entries(counting);
    let view = view(&kept_opened, roster_devices, removed);
    let kept = kept_opened.into_iter().map(|o| o.entry).collect();
    FleetRead {
        view,
        kept,
        refused,
    }
}

fn refusal(entry: &FleetEntry, reason: FleetRefused) -> Refusal {
    Refusal {
        author: entry.author,
        key: entry.key.clone(),
        reason,
    }
}

/// Opens an entry: unseals it, checks its statement, reads its record and
/// checks its slot.
fn open(
    identity: &[u8; PUBLIC_KEY_BYTES],
    fleet_key: &FleetKey,
    doc_id: &[u8; DOC_ID_BYTES],
    entry: &FleetEntry,
) -> Result<(Statement, FleetRecord), FleetRefused> {
    if entry.value.len() > MAX_SEALED_BYTES {
        return Err(FleetRefused::TooLarge);
    }
    if entry.key.len() != ENTRY_KEY_BYTES {
        return Err(FleetRefused::Misplaced);
    }
    let plaintext = fleet_key
        .open(&[doc_id, &entry.key], &entry.value)
        .ok_or(FleetRefused::NotSealed)?;
    let statement = Statement::open(
        &plaintext,
        Placement {
            doc_id,
            entry_key: &entry.key,
        },
    )?;
    let StatementKind::Fleet(kind) = statement.kind() else {
        return Err(FleetRefused::NotAFleetRecord);
    };
    let record = FleetRecord::decode(kind, statement.payload(), identity)?;
    if fleet_key.entry_key(&record.slot()) != entry.key.as_slice() {
        return Err(FleetRefused::Misplaced);
    }
    Ok((statement, record))
}

/// Enrolments of current devices that share a device, endpoint or author id
/// with a different one.
fn clashing_enrolments(
    opened: &[Opened],
    removed: &BTreeSet<DeviceId>,
) -> BTreeSet<DeviceEnrolment> {
    let enrolments: BTreeSet<DeviceEnrolment> = opened
        .iter()
        .filter_map(|o| match &o.record {
            FleetRecord::Enrolment(enrolment) if !removed.contains(&enrolment.device_id()) => {
                Some(*enrolment)
            }
            _ => None,
        })
        .collect();
    let mut by_key: BTreeMap<[u8; PUBLIC_KEY_BYTES], Vec<DeviceEnrolment>> = BTreeMap::new();
    for enrolment in &enrolments {
        for key in [
            enrolment.device_id(),
            enrolment.endpoint_id(),
            enrolment.author_id(),
        ] {
            by_key.entry(key).or_default().push(*enrolment);
        }
    }
    by_key
        .into_values()
        .filter(|sharing| sharing.len() > 1)
        .flatten()
        .collect()
}

/// Whether an opened entry counts.
fn counts(
    o: &Opened,
    roster: &BTreeMap<DeviceId, DeviceEnrolment>,
    removed: &BTreeSet<DeviceId>,
    clashing: &BTreeSet<DeviceEnrolment>,
) -> Result<(), FleetRefused> {
    match &o.record {
        FleetRecord::Enrolment(enrolment) if removed.contains(&enrolment.device_id()) => {
            Err(FleetRefused::Removed)
        }
        FleetRecord::Enrolment(enrolment) if clashing.contains(enrolment) => {
            Err(FleetRefused::Clashing)
        }
        record if record.is_the_accounts() => Ok(()),
        record => {
            if removed.contains(&o.signer) {
                return Err(FleetRefused::Removed);
            }
            let bound = roster
                .get(&o.signer)
                .is_some_and(|device| device.author_id() == o.entry.author);
            if !bound {
                return Err(FleetRefused::Unbound);
            }
            if let FleetRecord::Holding(holding) = record
                && holding.peer_heads.iter().any(|(peer, _)| *peer == o.signer)
            {
                return Err(FleetRefused::SelfPeer);
            }
            Ok(())
        }
    }
}

/// What a reader keeps: for a device's word, the newest statement per
/// signer and slot (highest sequence, then the greater entry, so every
/// reader keeps the same one); for an enrolment or a tombstone, one entry
/// per slot whoever signed its statement (the least, likewise), since any
/// copy carries the same record and a copier mustn't be able to make a
/// reader keep more; and for each vault, the one entry carrying its highest
/// epoch wherever it sits.
fn kept_entries(counting: Vec<Opened>) -> Vec<Opened> {
    type CarrierRank = (u64, [u8; DOC_ID_BYTES], Reverse<FleetEntry>);
    let mut newest: BTreeMap<(DeviceId, Vec<u8>), Opened> = BTreeMap::new();
    let mut accounts: BTreeMap<Vec<u8>, Opened> = BTreeMap::new();
    let mut carriers: BTreeMap<VaultId, (CarrierRank, Opened)> = BTreeMap::new();
    for o in counting {
        match &o.record {
            FleetRecord::VaultEpoch(epoch) => {
                let rank = (epoch.epoch(), epoch.doc_id(), Reverse(o.entry.clone()));
                match carriers.get(&epoch.vault_id()) {
                    Some((best, _)) if *best >= rank => {}
                    _ => {
                        carriers.insert(epoch.vault_id(), (rank, o));
                    }
                }
            }
            record if record.is_the_accounts() => match accounts.get(&o.entry.key) {
                Some(current) if current.entry <= o.entry => {}
                _ => {
                    accounts.insert(o.entry.key.clone(), o);
                }
            },
            _ => {
                let slot = (o.signer, o.entry.key.clone());
                match newest.get(&slot) {
                    Some(current)
                        if (current.sequence, &current.entry) >= (o.sequence, &o.entry) => {}
                    _ => {
                        newest.insert(slot, o);
                    }
                }
            }
        }
    }
    let mut kept: Vec<Opened> = newest
        .into_values()
        .chain(accounts.into_values())
        .chain(carriers.into_values().map(|(_, carrier)| carrier))
        .collect();
    kept.sort_by(|a, b| a.entry.cmp(&b.entry));
    kept
}

/// The latest of several records any device may set: highest sequence, then
/// higher signer.
fn latest<'a, T>(candidates: impl Iterator<Item = (&'a Opened, T)>) -> Option<T> {
    candidates
        .max_by(|(a, _), (b, _)| (a.sequence, a.signer).cmp(&(b.sequence, b.signer)))
        .map(|(_, record)| record)
}

fn view(
    kept: &[Opened],
    roster_devices: BTreeMap<DeviceId, DeviceEnrolment>,
    removed: BTreeSet<DeviceId>,
) -> FleetView {
    let devices = roster_devices
        .values()
        .map(|enrolment| {
            let id = enrolment.device_id();
            FleetDevice {
                enrolment: *enrolment,
                name: latest(kept.iter().filter_map(|o| match &o.record {
                    FleetRecord::DeviceName(name) if name.device_id == id => {
                        Some((o, name.name.clone()))
                    }
                    _ => None,
                })),
                info: latest(kept.iter().filter_map(|o| match &o.record {
                    FleetRecord::DeviceInfo(info) if o.signer == id => Some((o, info.clone())),
                    _ => None,
                })),
            }
        })
        .collect();

    let mut epochs: BTreeMap<VaultId, VaultEpoch> = BTreeMap::new();
    for o in kept {
        if let FleetRecord::VaultEpoch(epoch) = &o.record {
            let highest = epochs.entry(epoch.vault_id()).or_insert(*epoch);
            if (epoch.epoch(), epoch.doc_id()) > (highest.epoch(), highest.doc_id()) {
                *highest = *epoch;
            }
        }
    }
    let vaults = epochs
        .into_values()
        .map(|epoch| {
            let id = epoch.vault_id();
            let holdings = roster_devices
                .keys()
                .filter_map(|device| {
                    latest(kept.iter().filter_map(|o| match &o.record {
                        FleetRecord::Holding(holding)
                            if o.signer == *device && holding.vault_id == id =>
                        {
                            Some((o, holding.clone()))
                        }
                        _ => None,
                    }))
                    .map(|mut holding| {
                        // A peer is a claim about a device; only current
                        // devices' copies are anyone's to count.
                        holding
                            .peer_heads
                            .retain(|(peer, _)| roster_devices.contains_key(peer));
                        (*device, holding)
                    })
                })
                .collect();
            FleetVault {
                vault_id: id,
                epoch: epoch.epoch(),
                doc_id: epoch.doc_id(),
                look: latest(kept.iter().filter_map(|o| match &o.record {
                    FleetRecord::VaultLook(look) if look.vault_id == id => Some((o, look.clone())),
                    _ => None,
                })),
                holdings,
            }
        })
        .collect();

    let names: BTreeSet<&str> = kept
        .iter()
        .filter_map(|o| match &o.record {
            FleetRecord::Setting(setting) => Some(setting.name.as_str()),
            _ => None,
        })
        .collect();
    let settings = names
        .into_iter()
        .filter_map(|name| {
            latest(kept.iter().filter_map(|o| match &o.record {
                FleetRecord::Setting(setting) if setting.name == name => Some((o, setting)),
                _ => None,
            }))
            .map(|setting| FleetSetting {
                name: setting.name.clone(),
                value: setting.value.clone(),
            })
        })
        .collect();

    let roster = Roster::from_checked(roster_devices.into_values().collect())
        .expect("clashing enrolments are left out of the roster");
    FleetView {
        devices,
        removed: removed.into_iter().collect(),
        vaults,
        settings,
        roster,
    }
}
