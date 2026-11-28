//! A device-signed statement: what a device writes into an account's
//! documents, signed by its own signing key.
//!
//! The document layer underneath stamps every entry with an author, but an
//! author's secret lives in the document store, readable by anyone with a
//! copy of it, so an author says only "someone with this store wrote this".
//! What says which device wrote a value is this statement: the value,
//! signed by the device signing key that the device's enrolment certifies.
//!
//! The signature covers the statement's kind, its signer, a sequence number,
//! the payload, and where the statement belongs: the document id and the
//! entry key it is written under. The place isn't on the wire (the reader
//! knows where it found the statement), so a statement moved to another
//! document or key no longer verifies. The sequence lets a reader refuse to
//! go back: a reader keeps the highest sequence it has accepted for a place
//! and signer, and an older statement put back in front of it is refused.
//!
//! The byte form is `version ‖ kind ‖ signer ‖ sequence ‖ payload ‖
//! signature`, the sequence big-endian and the payload whatever lies between.
//! [`Statement::open`] parses and verifies in one step, so there is no way
//! to hold a statement that hasn't been checked.

use keys_pairing::keys::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES, ed25519_public_key_is_usable};
use keys_pairing::{DeviceStatement, DeviceSyncKeys};

/// The version of the statement format. There is one.
const STATEMENT_VERSION: u8 = 1;
/// Length of a document id.
pub const DOC_ID_BYTES: usize = 32;
/// Length of a sequence number on the wire.
const SEQUENCE_BYTES: usize = 8;
/// Everything in a statement but its payload: version, kind, signer,
/// sequence, signature.
const STATEMENT_OVERHEAD_BYTES: usize = 2 + PUBLIC_KEY_BYTES + SEQUENCE_BYTES + SIGNATURE_BYTES;
/// The longest payload a statement carries. Statements are small records;
/// anything bigger is content, which a statement names by hash.
pub const MAX_PAYLOAD_BYTES: usize = 1024;
/// The longest statement: what a reader may fetch before checking it.
pub const MAX_STATEMENT_BYTES: usize = STATEMENT_OVERHEAD_BYTES + MAX_PAYLOAD_BYTES;
/// The longest entry key a statement may be placed under.
pub const MAX_ENTRY_KEY_BYTES: usize = 64;

/// What a statement says, which fixes the label its signature is made under
/// and the shape of its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StatementKind {
    /// The head of a device's copy of a vault ([`crate::vault_head`]).
    VaultHead,
    /// A record in the account's fleet document ([`crate::fleet`]).
    Fleet(FleetKind),
}

/// The records of the fleet document ([`crate::fleet`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FleetKind {
    /// A device's enrolment, signed by the account identity key.
    Enrolment,
    /// A device's removal, signed by the account identity key.
    Tombstone,
    /// A vault's epoch and sync document, signed by the account identity key.
    VaultEpoch,
    /// What a device says about itself: its platform and when it was last seen.
    DeviceInfo,
    /// A device's name, which any device of the account may set.
    DeviceName,
    /// How a vault looks: its name, icon and colour.
    VaultLook,
    /// Which epoch of a vault a device holds, and the copies it has.
    Holding,
    /// One of the account's settings.
    Setting,
}

impl FleetKind {
    /// Every fleet record kind, in wire order.
    pub const ALL: [Self; 8] = [
        Self::Enrolment,
        Self::Tombstone,
        Self::VaultEpoch,
        Self::DeviceInfo,
        Self::DeviceName,
        Self::VaultLook,
        Self::Holding,
        Self::Setting,
    ];
}

impl StatementKind {
    /// The wire byte: 1 for a vault head, 2 to 9 for the fleet records in
    /// [`FleetKind::ALL`]'s order.
    pub(crate) const fn wire(self) -> u8 {
        match self {
            Self::VaultHead => 1,
            Self::Fleet(kind) => match kind {
                FleetKind::Enrolment => 2,
                FleetKind::Tombstone => 3,
                FleetKind::VaultEpoch => 4,
                FleetKind::DeviceInfo => 5,
                FleetKind::DeviceName => 6,
                FleetKind::VaultLook => 7,
                FleetKind::Holding => 8,
                FleetKind::Setting => 9,
            },
        }
    }

    const fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::VaultHead),
            2..=9 => Some(Self::Fleet(FleetKind::ALL[(byte - 2) as usize])),
            _ => None,
        }
    }

    const fn signed_as(self) -> DeviceStatement {
        match self {
            Self::VaultHead => DeviceStatement::VaultHead,
            // One label for the fleet records: the kind byte, which the
            // signature also covers, tells them apart.
            Self::Fleet(_) => DeviceStatement::FleetRecord,
        }
    }
}

/// Where a statement belongs: the document and the entry key it is written
/// under. Part of what the signature covers.
#[derive(Debug, Clone, Copy)]
pub struct Placement<'a> {
    pub doc_id: &'a [u8; DOC_ID_BYTES],
    pub entry_key: &'a [u8],
}

/// Why a statement was refused or couldn't be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StatementError {
    /// Not a statement's byte form: too short or too long, another version,
    /// a kind this build doesn't know, or a signer that isn't a usable key.
    #[error("not a device statement")]
    Malformed,
    /// The signature isn't its signer's over this statement in this place:
    /// forged, damaged, or moved from another document or entry key.
    #[error("the statement isn't signed by its device for this place")]
    NotSigned,
    /// The payload or entry key is longer than a statement allows; nothing
    /// is signed.
    #[error("the statement is too large")]
    TooLarge,
}

/// A statement that has been checked: signed by `signer` for the place it
/// was opened against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    kind: StatementKind,
    signer: [u8; PUBLIC_KEY_BYTES],
    sequence: u64,
    payload: Vec<u8>,
}

impl Statement {
    /// Signs `payload` as a statement of `kind` with sequence `sequence`, for
    /// `place`, with the device's signing key, and returns the byte form.
    ///
    /// # Errors
    /// [`StatementError::TooLarge`] if the payload or the entry key is over
    /// its limit.
    pub fn sign(
        keys: &DeviceSyncKeys,
        kind: StatementKind,
        sequence: u64,
        place: Placement<'_>,
        payload: &[u8],
    ) -> Result<Vec<u8>, StatementError> {
        if payload.len() > MAX_PAYLOAD_BYTES || place.entry_key.len() > MAX_ENTRY_KEY_BYTES {
            return Err(StatementError::TooLarge);
        }
        Ok(Self::sign_within_limits(
            keys, kind, sequence, place, payload,
        ))
    }

    /// [`Self::sign`] for a payload and entry key the caller knows are
    /// within their limits.
    pub(crate) fn sign_within_limits(
        keys: &DeviceSyncKeys,
        kind: StatementKind,
        sequence: u64,
        place: Placement<'_>,
        payload: &[u8],
    ) -> Vec<u8> {
        debug_assert!(payload.len() <= MAX_PAYLOAD_BYTES);
        debug_assert!(place.entry_key.len() <= MAX_ENTRY_KEY_BYTES);
        let signer = keys.signing_public_key();
        let signature = with_signed_fields(kind, &signer, sequence, place, payload, |fields| {
            keys.sign_statement(kind.signed_as(), fields)
        });
        let mut out = Vec::with_capacity(STATEMENT_OVERHEAD_BYTES + payload.len());
        out.push(STATEMENT_VERSION);
        out.push(kind.wire());
        out.extend_from_slice(&signer);
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&signature);
        out
    }

    /// Reads a statement's byte form found at `place` and checks its
    /// signature.
    ///
    /// # Errors
    /// [`StatementError::Malformed`] if it isn't a statement's byte form,
    /// [`StatementError::NotSigned`] if its signature doesn't verify for
    /// this place.
    pub fn open(bytes: &[u8], place: Placement<'_>) -> Result<Self, StatementError> {
        if bytes.len() > MAX_STATEMENT_BYTES || place.entry_key.len() > MAX_ENTRY_KEY_BYTES {
            return Err(StatementError::Malformed);
        }
        let (&[version, kind], rest) = bytes
            .split_first_chunk::<2>()
            .ok_or(StatementError::Malformed)?;
        if version != STATEMENT_VERSION {
            return Err(StatementError::Malformed);
        }
        let kind = StatementKind::from_wire(kind).ok_or(StatementError::Malformed)?;
        let (&signer, rest) = rest
            .split_first_chunk::<PUBLIC_KEY_BYTES>()
            .ok_or(StatementError::Malformed)?;
        let (&sequence, rest) = rest
            .split_first_chunk::<SEQUENCE_BYTES>()
            .ok_or(StatementError::Malformed)?;
        let (payload, &signature) = rest
            .split_last_chunk::<SIGNATURE_BYTES>()
            .ok_or(StatementError::Malformed)?;
        if !ed25519_public_key_is_usable(&signer) {
            return Err(StatementError::Malformed);
        }
        let sequence = u64::from_be_bytes(sequence);
        let verified = with_signed_fields(kind, &signer, sequence, place, payload, |fields| {
            kind.signed_as().verify(&signer, fields, &signature)
        });
        if !verified {
            return Err(StatementError::NotSigned);
        }
        Ok(Self {
            kind,
            signer,
            sequence,
            payload: payload.to_vec(),
        })
    }

    #[must_use]
    pub fn kind(&self) -> StatementKind {
        self.kind
    }

    /// The device signing key that signed it: the device's id.
    #[must_use]
    pub fn signer(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.signer
    }

    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// The sequence for a device's next statement in a place: above the last one
/// it made there, and no lower than its clock's reading, in microseconds
/// since the Unix epoch. The clock floor means a device that has lost track
/// of its last statement still moves forward; the step above `previous`
/// means one whose clock went back does too. `None` once `previous` is the
/// last sequence there is: no statement in that place could be accepted
/// after it.
#[must_use]
pub fn next_sequence(previous: Option<u64>, now_micros: u64) -> Option<u64> {
    match previous {
        None => Some(now_micros),
        Some(previous) => previous.checked_add(1).map(|above| above.max(now_micros)),
    }
}

/// Calls `f` with what the signature covers: the format version, the kind,
/// the signer, the sequence, the place and the payload, each a field of its
/// own.
fn with_signed_fields<R>(
    kind: StatementKind,
    signer: &[u8; PUBLIC_KEY_BYTES],
    sequence: u64,
    place: Placement<'_>,
    payload: &[u8],
    f: impl FnOnce(&[&[u8]]) -> R,
) -> R {
    let version = [STATEMENT_VERSION];
    let kind = [kind.wire()];
    let sequence = sequence.to_be_bytes();
    f(&[
        &version,
        &kind,
        signer,
        &sequence,
        place.doc_id,
        place.entry_key,
        payload,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{kat_device_sync, unhex};
    use keys_pairing::DeviceKeys;

    const DOC: [u8; DOC_ID_BYTES] = [0xd0; DOC_ID_BYTES];
    const KEY: &[u8] = b"keys/v1/test";

    #[test]
    fn every_kind_has_a_wire_byte_of_its_own() {
        let kinds: Vec<StatementKind> = std::iter::once(StatementKind::VaultHead)
            .chain(FleetKind::ALL.map(StatementKind::Fleet))
            .collect();
        for (index, kind) in kinds.iter().enumerate() {
            assert_eq!(StatementKind::from_wire(kind.wire()), Some(*kind));
            assert!(
                kinds[index + 1..]
                    .iter()
                    .all(|other| other.wire() != kind.wire())
            );
        }
        assert_eq!(StatementKind::from_wire(0), None);
        assert_eq!(StatementKind::from_wire(10), None);
    }

    fn place() -> Placement<'static> {
        Placement {
            doc_id: &DOC,
            entry_key: KEY,
        }
    }

    fn signed(sequence: u64, payload: &[u8]) -> (DeviceKeys, Vec<u8>) {
        let device = DeviceKeys::generate().expect("rng");
        let bytes = Statement::sign(
            device.sync_keys(),
            StatementKind::VaultHead,
            sequence,
            place(),
            payload,
        )
        .expect("signs");
        (device, bytes)
    }

    #[test]
    fn a_statement_opens_where_it_was_signed() {
        let (device, bytes) = signed(7, b"payload");
        let statement = Statement::open(&bytes, place()).expect("opens");
        assert_eq!(statement.kind(), StatementKind::VaultHead);
        assert_eq!(statement.signer(), device.public_keys().signing);
        assert_eq!(statement.sequence(), 7);
        assert_eq!(statement.payload(), b"payload");
    }

    #[test]
    fn an_empty_payload_is_a_statement_too() {
        let (_, bytes) = signed(0, b"");
        assert_eq!(bytes.len(), STATEMENT_OVERHEAD_BYTES);
        assert!(Statement::open(&bytes, place()).is_ok());
    }

    #[test]
    fn a_statement_moved_to_another_document_or_key_is_refused() {
        let (_, bytes) = signed(7, b"payload");
        let other_doc = [0xd1; DOC_ID_BYTES];
        for moved in [
            Placement {
                doc_id: &other_doc,
                entry_key: KEY,
            },
            Placement {
                doc_id: &DOC,
                entry_key: b"keys/v1/tesu",
            },
            Placement {
                doc_id: &DOC,
                entry_key: b"",
            },
        ] {
            assert_eq!(
                Statement::open(&bytes, moved),
                Err(StatementError::NotSigned)
            );
        }
    }

    /// Every bit of the byte form is covered: flipping any one is refused,
    /// as malformed (version, kind, a signer that is no longer a usable key)
    /// or as not signed (everything else).
    #[test]
    fn every_altered_bit_is_refused() {
        let (_, bytes) = signed(7, b"payload");
        for index in 0..bytes.len() {
            for bit in 0..8 {
                let mut altered = bytes.clone();
                altered[index] ^= 1 << bit;
                assert!(
                    Statement::open(&altered, place()).is_err(),
                    "bit {bit} of byte {index} went unnoticed"
                );
            }
        }
    }

    #[test]
    fn truncated_extended_and_foreign_forms_are_refused() {
        let (_, bytes) = signed(7, b"payload");
        for len in 0..STATEMENT_OVERHEAD_BYTES {
            assert_eq!(
                Statement::open(&bytes[..len], place()),
                Err(StatementError::Malformed),
                "{len} bytes"
            );
        }
        // Cut short past the overhead, the payload shrinks and the
        // signature is read from the wrong bytes.
        assert_eq!(
            Statement::open(&bytes[..bytes.len() - 1], place()),
            Err(StatementError::NotSigned)
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            Statement::open(&longer, place()),
            Err(StatementError::NotSigned)
        );

        let mut version = bytes.clone();
        version[0] = 2;
        assert_eq!(
            Statement::open(&version, place()),
            Err(StatementError::Malformed)
        );
        let mut kind = bytes;
        kind[1] = 0;
        assert_eq!(
            Statement::open(&kind, place()),
            Err(StatementError::Malformed)
        );
    }

    #[test]
    fn nothing_over_the_limits_is_signed_or_read() {
        let device = DeviceKeys::generate().expect("rng");
        let sign = |payload: &[u8], entry_key: &[u8]| {
            Statement::sign(
                device.sync_keys(),
                StatementKind::VaultHead,
                1,
                Placement {
                    doc_id: &DOC,
                    entry_key,
                },
                payload,
            )
        };
        let longest = sign(&[0; MAX_PAYLOAD_BYTES], &[0; MAX_ENTRY_KEY_BYTES]).expect("fits");
        assert_eq!(longest.len(), MAX_STATEMENT_BYTES);
        assert_eq!(
            sign(&[0; MAX_PAYLOAD_BYTES + 1], KEY),
            Err(StatementError::TooLarge)
        );
        assert_eq!(
            sign(b"", &[0; MAX_ENTRY_KEY_BYTES + 1]),
            Err(StatementError::TooLarge)
        );

        let mut over = longest;
        over.push(0);
        assert_eq!(
            Statement::open(&over, place()),
            Err(StatementError::Malformed)
        );
        let (_, bytes) = signed(1, b"");
        assert_eq!(
            Statement::open(
                &bytes,
                Placement {
                    doc_id: &DOC,
                    entry_key: &[0; MAX_ENTRY_KEY_BYTES + 1],
                }
            ),
            Err(StatementError::Malformed)
        );
    }

    /// A signer that isn't a usable key is refused before any signature
    /// check: the identity point, and a real key plus a point of order 8
    /// (which its holder could sign for under a second byte string).
    #[test]
    fn a_signer_that_isnt_a_usable_key_is_refused() {
        let (device, bytes) = signed(7, b"payload");
        let signer = device.public_keys().signing;
        let torsioned = (curve25519_dalek::edwards::CompressedEdwardsY(signer)
            .decompress()
            .expect("on the curve")
            + curve25519_dalek::constants::EIGHT_TORSION[1])
            .compress()
            .to_bytes();
        let mut identity = [0u8; PUBLIC_KEY_BYTES];
        identity[0] = 1;
        for bad in [identity, torsioned] {
            let mut altered = bytes.clone();
            altered[2..2 + PUBLIC_KEY_BYTES].copy_from_slice(&bad);
            assert_eq!(
                Statement::open(&altered, place()),
                Err(StatementError::Malformed)
            );
        }
    }

    #[test]
    fn the_next_sequence_moves_forward_whatever_the_clock_does() {
        assert_eq!(next_sequence(None, 1_000), Some(1_000));
        assert_eq!(next_sequence(Some(500), 1_000), Some(1_000));
        // The clock went back, or two statements in one microsecond.
        assert_eq!(next_sequence(Some(1_000), 1_000), Some(1_001));
        assert_eq!(next_sequence(Some(5_000), 1_000), Some(5_001));
        // Nothing comes after the last sequence there is.
        assert_eq!(next_sequence(Some(u64::MAX - 1), 1_000), Some(u64::MAX));
        assert_eq!(next_sequence(Some(u64::MAX), 1_000), None);
    }

    /// The device signing key from seed `[0x44; 32]`, document id `0xd0`s,
    /// entry key `keys/v1/test`, sequence 7, payload `payload`. Computed
    /// independently of this crate.
    #[test]
    fn statement_known_answer() {
        let bytes = Statement::sign(
            &kat_device_sync(),
            StatementKind::VaultHead,
            7,
            place(),
            b"payload",
        )
        .expect("signs");
        assert_eq!(bytes, unhex(KAT_STATEMENT));
        assert!(Statement::open(&unhex(KAT_STATEMENT), place()).is_ok());
    }

    const KAT_STATEMENT: &str = concat!(
        "0101",
        "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48",
        "0000000000000007",
        "7061796c6f6164",
        "9b8b9521c82c65250995f56e89ad788b50eb1ffff347832f2d839e0f39af9576",
        "716beba692feabf4994d96a64ff4b2318afb255b1a26ec9c44039faba380bd09",
    );
}
