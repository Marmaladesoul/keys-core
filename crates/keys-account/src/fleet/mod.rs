//! The account's fleet document: one per account, written by all of its
//! devices, holding the roster, the tombstones, the vault index, what each
//! device holds, and the account's settings.
//!
//! **Every value is sealed** under the account's fleet key
//! ([`keys_pairing::FleetKey`]), bound to its document and entry key, and
//! every entry key is the fleet key's name for the record's slot
//! ([`record`]), so whoever holds the document's id, its write ticket or a
//! copy of a device's store sees ciphertext under opaque keys. Inside the
//! seal each value is a device statement ([`crate::statement`]): signed by
//! the device that wrote it, for this document and entry key, with a
//! sequence that only goes up.
//!
//! A device writes its records under its own author, and seals and signs
//! each with [`seal_record`]. A reader fetches every entry small enough to
//! be a record ([`fleet_entry_to_fetch`]), from any author: the roster that
//! says which authors are bound is itself in the document. It then reads
//! them all at once with [`read_fleet`] ([`read`] has the rules).
//!
//! The sequence is the writer's clock: a device takes
//! [`crate::next_sequence`] of the last sequence it used anywhere in the
//! document and its clock in microseconds, so its sequences only go up in
//! every slot. Where any device may set a record (a name, a vault's look, a
//! setting), the latest sequence wins.

pub mod read;
pub mod record;

use keys_pairing::DeviceSyncKeys;
use keys_pairing::FleetKey;
use keys_pairing::fleet_key::{ENTRY_KEY_BYTES, SEALED_OVERHEAD_BYTES};

use crate::statement::{DOC_ID_BYTES, MAX_STATEMENT_BYTES, Placement, Statement, StatementKind};
pub use read::{
    FleetDevice, FleetEntry, FleetRead, FleetRefused, FleetSetting, FleetVault, FleetView, Refusal,
    read_fleet,
};
pub use record::{
    DeviceId, DeviceInfo, DeviceName, FleetRecord, HeadHash, Holding, RecordError, Setting,
    Tombstone, VaultEpoch, VaultId, VaultLook,
};

/// The longest fleet value: a sealed statement. A reader fetches nothing
/// longer.
pub const MAX_SEALED_BYTES: usize = SEALED_OVERHEAD_BYTES + MAX_STATEMENT_BYTES;
/// How often a device rewrites when it was last seen: every device's copy
/// of the document carries it, so it is a presence feed, not a heartbeat.
pub const LAST_SEEN_INTERVAL_MICROS: u64 = 3_600_000_000;

/// A record as written: the entry key to write it under, and the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRecord {
    pub key: [u8; ENTRY_KEY_BYTES],
    pub value: Vec<u8>,
}

/// Why a record couldn't be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error(transparent)]
    Record(#[from] RecordError),
    /// The system random source failed.
    #[error("the system random source failed")]
    Random,
}

/// Signs `record` with the device's signing key at `sequence`, for its slot
/// in document `doc_id`, and seals it under the fleet key. The caller writes
/// the value under the returned key, with its own author.
///
/// # Errors
/// [`SealError::Record`] if the record isn't in its canonical form
/// ([`FleetRecord::encode`]) or is a holding that lists this device as a
/// peer, [`SealError::Random`] if the system random
/// source fails.
pub fn seal_record(
    fleet_key: &FleetKey,
    doc_id: &[u8; DOC_ID_BYTES],
    keys: &DeviceSyncKeys,
    sequence: u64,
    record: &FleetRecord,
) -> Result<SealedRecord, SealError> {
    if let FleetRecord::Holding(holding) = record
        && holding
            .peer_heads
            .iter()
            .any(|(peer, _)| *peer == keys.signing_public_key())
    {
        return Err(RecordError::Invalid.into());
    }
    let payload = record.encode()?;
    let key = fleet_key.entry_key(&record.slot());
    let statement = Statement::sign_within_limits(
        keys,
        StatementKind::Fleet(record.kind()),
        sequence,
        Placement {
            doc_id,
            entry_key: &key,
        },
        &payload,
    );
    let value = fleet_key
        .seal(&[doc_id, &key], &statement)
        .map_err(|_| SealError::Random)?;
    debug_assert!(value.len() <= MAX_SEALED_BYTES);
    Ok(SealedRecord { key, value })
}

/// Whether a reader fetches an entry whose recorded size is `size_bytes`:
/// anything small enough to be a fleet record, from any author.
#[must_use]
pub fn fleet_entry_to_fetch(size_bytes: u64) -> bool {
    size_bytes <= MAX_SEALED_BYTES as u64
}

/// Whether a device whose last-seen time was last written at
/// `last_written` (microseconds, its own clock) should write it again at
/// `now`: if it never has, or an hour has passed, or its clock went back.
#[must_use]
pub fn last_seen_due(last_written: Option<u64>, now: u64) -> bool {
    last_written.is_none_or(|last| now < last || now - last >= LAST_SEEN_INTERVAL_MICROS)
}

// Entry keys fit a statement's placement.
const _: () = assert!(ENTRY_KEY_BYTES <= crate::statement::MAX_ENTRY_KEY_BYTES);

#[cfg(test)]
mod tests;
