//! A vault document's head records, and the two checks a reader makes before
//! it trusts or fetches anything in one.
//!
//! Each device that publishes a copy of a vault writes two entries under its
//! own author: the copy itself under [`VAULT_COPY_KEY`], and a small
//! [`StatementKind::VaultHead`] statement under [`VAULT_HEAD_KEY`] that names
//! the copy's content hash and size, signed by the device. Entries are kept
//! per author and key, so every device uses the same two keys and no device
//! id appears in a key.
//!
//! A reader joins the document with nothing downloaded by default and goes
//! in two steps:
//!
//! 1. [`head_to_fetch`]: from the entry's metadata alone (its author, key and
//!    recorded size), whether the entry is a head from a device in the
//!    account's [`Roster`] and small enough to be one. Nothing else is
//!    fetched, so a stranger's entries cost nothing.
//! 2. [`accept_vault_head`]: once the head is fetched, whether it is signed
//!    by the very device its author is bound to, for this document, newer
//!    than any head from that device the reader has accepted, and naming a
//!    copy within the reader's cap. Only then is the copy fetched, by the
//!    hash the head names and with the head's size as its cap.
//!
//! The owner of a copy is the device that signed its head; neither the
//! entry's key nor its author alone says anything about who wrote it.

use keys_pairing::DeviceSyncKeys;
use keys_pairing::keys::PUBLIC_KEY_BYTES;

use crate::enrolment::{DeviceEnrolment, EnrolmentError};
use crate::statement::{
    DOC_ID_BYTES, MAX_STATEMENT_BYTES, Placement, Statement, StatementError, StatementKind,
};

/// The entry key every device writes its head record under.
pub const VAULT_HEAD_KEY: &[u8] = b"keys/v1/vault/head";
/// The entry key every device writes its copy of the vault under.
pub const VAULT_COPY_KEY: &[u8] = b"keys/v1/vault/copy";
/// Length of a content hash (the document layer's BLAKE3).
pub const CONTENT_HASH_BYTES: usize = 32;
/// Length of a copy's size on the wire.
const SIZE_BYTES: usize = 8;
/// A head's payload: the copy's content hash and its size, big-endian.
const VAULT_HEAD_PAYLOAD_BYTES: usize = CONTENT_HASH_BYTES + SIZE_BYTES;

/// What a head says about a device's copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultHead {
    /// The copy's content hash, which is how the copy is fetched.
    pub content_hash: [u8; CONTENT_HASH_BYTES],
    /// The copy's size in bytes, which a reader checks against its cap
    /// before fetching and then fetches with as the cap.
    pub size: u64,
}

impl VaultHead {
    fn to_payload(self) -> [u8; VAULT_HEAD_PAYLOAD_BYTES] {
        let mut out = [0u8; VAULT_HEAD_PAYLOAD_BYTES];
        out[..CONTENT_HASH_BYTES].copy_from_slice(&self.content_hash);
        out[CONTENT_HASH_BYTES..].copy_from_slice(&self.size.to_be_bytes());
        out
    }

    fn from_payload(payload: &[u8]) -> Option<Self> {
        let (&content_hash, rest) = payload.split_first_chunk::<CONTENT_HASH_BYTES>()?;
        let &size: &[u8; SIZE_BYTES] = rest.try_into().ok()?;
        Some(Self {
            content_hash,
            size: u64::from_be_bytes(size),
        })
    }
}

/// Why a roster couldn't be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RosterError {
    /// An enrolment didn't open against the account.
    #[error("an enrolment was refused: {0}")]
    Enrolment(#[from] EnrolmentError),
    /// Two enrolments share a key: a device id, endpoint id or author id
    /// that is also another device's. Each must name one device.
    #[error("two enrolments share a key")]
    SharedKey,
}

/// The devices of one account, each from an enrolment checked against the
/// account's identity key, no two sharing a device id, endpoint id or author
/// id, so an author names at most one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    devices: Vec<DeviceEnrolment>,
}

impl Roster {
    /// Opens each of `enrolments` against the account whose identity key is
    /// `account_identity`.
    ///
    /// The same enrolment given more than once counts once, so a copy
    /// written twice can't refuse the roster. Two *different* enrolments of
    /// one device, or of two devices sharing a key, are refused: which of a
    /// device's enrolments is current is the caller's to settle before it
    /// builds the roster.
    ///
    /// # Errors
    /// [`RosterError`] if any enrolment is refused, or two share a key. One
    /// bad enrolment refuses the whole roster rather than being dropped, so
    /// a caller never acts on a roster that silently lost a device.
    pub fn open<'a>(
        account_identity: &[u8; PUBLIC_KEY_BYTES],
        enrolments: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, RosterError> {
        let mut devices: Vec<DeviceEnrolment> = Vec::new();
        for bytes in enrolments {
            let enrolment = DeviceEnrolment::open(bytes, account_identity)?;
            if !devices.contains(&enrolment) {
                devices.push(enrolment);
            }
        }
        let mut keys: Vec<[u8; PUBLIC_KEY_BYTES]> = devices
            .iter()
            .flat_map(|d| [d.device_id(), d.endpoint_id(), d.author_id()])
            .collect();
        let count = keys.len();
        keys.sort_unstable();
        keys.dedup();
        if keys.len() != count {
            return Err(RosterError::SharedKey);
        }
        Ok(Self { devices })
    }

    /// The device whose enrolment binds `author`, if any.
    #[must_use]
    pub fn device_by_author(&self, author: &[u8; PUBLIC_KEY_BYTES]) -> Option<&DeviceEnrolment> {
        self.devices.iter().find(|d| d.author_id() == *author)
    }

    #[must_use]
    pub fn devices(&self) -> &[DeviceEnrolment] {
        &self.devices
    }
}

/// Why an entry isn't fetched as a head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeadIgnored {
    /// It isn't under [`VAULT_HEAD_KEY`].
    #[error("not a head record")]
    NotAHead,
    /// Its author isn't bound to any device in the roster.
    #[error("written by an author the account doesn't know")]
    UnboundAuthor,
    /// It records a size no head can have.
    #[error("too large to be a head record")]
    TooLarge,
}

/// Step one: whether the entry at `entry_key`, written by `author` and
/// recording `size_bytes` of content, should be fetched as a head. Answers
/// with the device its author is bound to.
///
/// # Errors
/// [`HeadIgnored`] if it is not to be fetched.
pub fn head_to_fetch(
    roster: &Roster,
    author: &[u8; PUBLIC_KEY_BYTES],
    entry_key: &[u8],
    size_bytes: u64,
) -> Result<[u8; PUBLIC_KEY_BYTES], HeadIgnored> {
    if entry_key != VAULT_HEAD_KEY {
        return Err(HeadIgnored::NotAHead);
    }
    let device = roster
        .device_by_author(author)
        .ok_or(HeadIgnored::UnboundAuthor)?;
    if size_bytes > MAX_STATEMENT_BYTES as u64 {
        return Err(HeadIgnored::TooLarge);
    }
    Ok(device.device_id())
}

/// Why a fetched head was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeadRefused {
    /// It isn't a statement signed by its signer for this document's head.
    #[error(transparent)]
    Statement(#[from] StatementError),
    /// Its author isn't bound to any device in the roster.
    #[error("written by an author the account doesn't know")]
    UnboundAuthor,
    /// It is a statement, but not a head.
    #[error("not a head record")]
    NotAHead,
    /// It is signed by a device other than the one its author is bound to:
    /// a statement copied under another author, or a forgery by someone
    /// holding that author's secret.
    #[error("signed by a device other than its author's")]
    NotItsDevice,
    /// Its sequence isn't above the last head accepted from this device in
    /// this document: an old head put back, or one already seen.
    #[error("not newer than the head already accepted")]
    NotNewer,
    /// It names a copy larger than the reader's cap.
    #[error("the copy it names is over the cap")]
    CopyTooLarge,
}

/// A head that passed every check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedHead {
    /// The device that signed it: the copy's owner.
    pub device_id: [u8; PUBLIC_KEY_BYTES],
    /// Its sequence, for the reader to keep as the last accepted.
    pub sequence: u64,
    pub head: VaultHead,
}

/// Step two: whether `bytes`, the content of a head entry in document
/// `doc_id` written by `author`, is a head to act on. `last_accepted` is the
/// sequence of the last head the reader accepted from the same device in
/// this document; `max_copy_bytes` is the most the reader will fetch for a
/// copy.
///
/// # Errors
/// [`HeadRefused`] if it is not to be acted on.
pub fn accept_vault_head(
    roster: &Roster,
    doc_id: &[u8; DOC_ID_BYTES],
    author: &[u8; PUBLIC_KEY_BYTES],
    bytes: &[u8],
    last_accepted: Option<u64>,
    max_copy_bytes: u64,
) -> Result<AcceptedHead, HeadRefused> {
    let device = roster
        .device_by_author(author)
        .ok_or(HeadRefused::UnboundAuthor)?;
    let statement = Statement::open(bytes, head_place(doc_id))?;
    if statement.kind() != StatementKind::VaultHead {
        return Err(HeadRefused::NotAHead);
    }
    if statement.signer() != device.device_id() {
        return Err(HeadRefused::NotItsDevice);
    }
    if last_accepted.is_some_and(|last| statement.sequence() <= last) {
        return Err(HeadRefused::NotNewer);
    }
    let head = VaultHead::from_payload(statement.payload()).ok_or(HeadRefused::NotAHead)?;
    if head.size > max_copy_bytes {
        return Err(HeadRefused::CopyTooLarge);
    }
    Ok(AcceptedHead {
        device_id: statement.signer(),
        sequence: statement.sequence(),
        head,
    })
}

/// Signs `head` as this device's head record in document `doc_id`, with
/// sequence `sequence` (see [`crate::statement::next_sequence`]).
#[must_use]
pub fn sign_vault_head(
    keys: &DeviceSyncKeys,
    doc_id: &[u8; DOC_ID_BYTES],
    sequence: u64,
    head: VaultHead,
) -> Vec<u8> {
    // Within the limits: see the assertions at the end of this module.
    Statement::sign_within_limits(
        keys,
        StatementKind::VaultHead,
        sequence,
        head_place(doc_id),
        &head.to_payload(),
    )
}

fn head_place(doc_id: &[u8; DOC_ID_BYTES]) -> Placement<'_> {
    Placement {
        doc_id,
        entry_key: VAULT_HEAD_KEY,
    }
}

// A head always fits in a statement.
const _: () = assert!(VAULT_HEAD_PAYLOAD_BYTES <= crate::statement::MAX_PAYLOAD_BYTES);
const _: () = assert!(VAULT_HEAD_KEY.len() <= crate::statement::MAX_ENTRY_KEY_BYTES);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{kat_device_sync, unhex, usable_ed25519};
    use keys_pairing::{AccountKeys, DeviceKeys};

    const DOC: [u8; DOC_ID_BYTES] = [0xd0; DOC_ID_BYTES];
    const CAP: u64 = 1 << 20;
    const HEAD: VaultHead = VaultHead {
        content_hash: [0xc0; CONTENT_HASH_BYTES],
        size: 4096,
    };

    /// One device of an account: its keys and its enrolment.
    struct Enrolled {
        keys: DeviceKeys,
        enrolment: DeviceEnrolment,
    }

    impl Enrolled {
        fn new(account: &AccountKeys) -> Self {
            let keys = DeviceKeys::generate().expect("rng");
            let enrolment = DeviceEnrolment::sign(
                account,
                keys.public_keys(),
                usable_ed25519(),
                usable_ed25519(),
            )
            .expect("enrols");
            Self { keys, enrolment }
        }

        fn author(&self) -> [u8; PUBLIC_KEY_BYTES] {
            self.enrolment.author_id()
        }

        fn head(&self, sequence: u64, head: VaultHead) -> Vec<u8> {
            sign_vault_head(self.keys.sync_keys(), &DOC, sequence, head)
        }
    }

    /// An account with two enrolled devices, and its roster.
    fn account() -> (AccountKeys, Enrolled, Enrolled, Roster) {
        let (account, _) = AccountKeys::generate().expect("rng");
        let (a, b) = (Enrolled::new(&account), Enrolled::new(&account));
        let roster = Roster::open(
            &account.public_keys().identity,
            [
                a.enrolment.to_bytes().as_slice(),
                b.enrolment.to_bytes().as_slice(),
            ],
        )
        .expect("roster");
        (account, a, b, roster)
    }

    #[test]
    fn a_roster_binds_each_author_to_its_device() {
        let (_, a, b, roster) = account();
        assert_eq!(roster.devices().len(), 2);
        assert_eq!(
            roster
                .device_by_author(&a.author())
                .map(DeviceEnrolment::device_id),
            Some(a.keys.public_keys().signing)
        );
        assert_eq!(
            roster
                .device_by_author(&b.author())
                .map(DeviceEnrolment::device_id),
            Some(b.keys.public_keys().signing)
        );
        assert_eq!(roster.device_by_author(&usable_ed25519()), None);
    }

    #[test]
    fn a_roster_with_a_refused_enrolment_is_refused_whole() {
        let (account, a, _, _) = account();
        let (other_account, _) = AccountKeys::generate().expect("rng");
        let stranger = Enrolled::new(&other_account);
        assert_eq!(
            Roster::open(
                &account.public_keys().identity,
                [
                    a.enrolment.to_bytes().as_slice(),
                    stranger.enrolment.to_bytes().as_slice(),
                ],
            ),
            Err(RosterError::Enrolment(EnrolmentError::NotSignedByAccount))
        );
    }

    /// No key names two devices: not an author claimed twice, not one
    /// device's author that is another's endpoint or id, and not a second
    /// enrolment of the same device.
    #[test]
    fn a_roster_where_two_devices_share_a_key_is_refused() {
        let (account, _) = AccountKeys::generate().expect("rng");
        let identity = account.public_keys().identity;
        let a = Enrolled::new(&account);
        let enrol = |endpoint, author| {
            DeviceEnrolment::sign(
                &account,
                DeviceKeys::generate().expect("rng").public_keys(),
                endpoint,
                author,
            )
            .expect("enrols")
            .to_bytes()
        };
        for clash in [
            enrol(usable_ed25519(), a.author()),
            enrol(a.author(), usable_ed25519()),
            enrol(usable_ed25519(), a.enrolment.device_id()),
            enrol(a.enrolment.endpoint_id(), usable_ed25519()),
        ] {
            assert_eq!(
                Roster::open(
                    &identity,
                    [a.enrolment.to_bytes().as_slice(), clash.as_slice()]
                ),
                Err(RosterError::SharedKey)
            );
        }
    }

    /// A second enrolment of the same device, with a new author: refused,
    /// since which one is current isn't the roster's to guess. The same
    /// enrolment twice counts once.
    #[test]
    fn a_device_enrolled_twice_is_refused_but_a_repeated_enrolment_counts_once() {
        let (account, _) = AccountKeys::generate().expect("rng");
        let identity = account.public_keys().identity;
        let a = Enrolled::new(&account);
        let again = DeviceEnrolment::sign(
            &account,
            a.keys.public_keys(),
            usable_ed25519(),
            usable_ed25519(),
        )
        .expect("enrols")
        .to_bytes();
        let first = a.enrolment.to_bytes();
        assert_eq!(
            Roster::open(&identity, [first.as_slice(), again.as_slice()]),
            Err(RosterError::SharedKey)
        );
        let roster =
            Roster::open(&identity, [first.as_slice(), first.as_slice()]).expect("one device");
        assert_eq!(roster.devices(), &[a.enrolment]);
    }

    #[test]
    fn only_a_bound_author_s_head_sized_head_entry_is_fetched() {
        let (_, a, _, roster) = account();
        assert_eq!(
            head_to_fetch(&roster, &a.author(), VAULT_HEAD_KEY, 200),
            Ok(a.keys.public_keys().signing)
        );
        assert_eq!(
            head_to_fetch(&roster, &a.author(), VAULT_COPY_KEY, 200),
            Err(HeadIgnored::NotAHead)
        );
        assert_eq!(
            head_to_fetch(&roster, &usable_ed25519(), VAULT_HEAD_KEY, 200),
            Err(HeadIgnored::UnboundAuthor)
        );
        assert_eq!(
            head_to_fetch(
                &roster,
                &a.author(),
                VAULT_HEAD_KEY,
                MAX_STATEMENT_BYTES as u64
            ),
            Ok(a.keys.public_keys().signing)
        );
        assert_eq!(
            head_to_fetch(
                &roster,
                &a.author(),
                VAULT_HEAD_KEY,
                MAX_STATEMENT_BYTES as u64 + 1
            ),
            Err(HeadIgnored::TooLarge)
        );
    }

    #[test]
    fn a_device_s_head_under_its_author_is_accepted() {
        let (_, a, _, roster) = account();
        let accepted = accept_vault_head(&roster, &DOC, &a.author(), &a.head(9, HEAD), None, CAP)
            .expect("accepted");
        assert_eq!(
            accepted,
            AcceptedHead {
                device_id: a.keys.public_keys().signing,
                sequence: 9,
                head: HEAD,
            }
        );
        // A newer one after it.
        assert!(
            accept_vault_head(&roster, &DOC, &a.author(), &a.head(10, HEAD), Some(9), CAP).is_ok()
        );
    }

    /// Someone holding device A's author secret (a copy of its store) can
    /// write under A's author, but can't sign as A: a head signed by
    /// another enrolled device, or by a key that is no device's, is refused,
    /// and so is A's genuine head copied under B's author.
    #[test]
    fn a_head_signed_by_anyone_but_its_author_s_device_is_refused() {
        let (_, a, b, roster) = account();
        let stranger = DeviceKeys::generate().expect("rng");
        let forged = sign_vault_head(stranger.sync_keys(), &DOC, 9, HEAD);
        for (author, bytes) in [
            (a.author(), b.head(9, HEAD)),
            (a.author(), forged),
            (b.author(), a.head(9, HEAD)),
        ] {
            assert_eq!(
                accept_vault_head(&roster, &DOC, &author, &bytes, None, CAP),
                Err(HeadRefused::NotItsDevice)
            );
        }
        assert_eq!(
            accept_vault_head(
                &roster,
                &DOC,
                &usable_ed25519(),
                &a.head(9, HEAD),
                None,
                CAP
            ),
            Err(HeadRefused::UnboundAuthor)
        );
    }

    #[test]
    fn a_head_from_another_document_is_refused() {
        let (_, a, _, roster) = account();
        let other = sign_vault_head(a.keys.sync_keys(), &[0xd1; DOC_ID_BYTES], 9, HEAD);
        assert_eq!(
            accept_vault_head(&roster, &DOC, &a.author(), &other, None, CAP),
            Err(HeadRefused::Statement(StatementError::NotSigned))
        );
    }

    #[test]
    fn an_old_head_put_back_is_refused() {
        let (_, a, _, roster) = account();
        for (sequence, last) in [(9, 9), (8, 9), (0, u64::MAX)] {
            assert_eq!(
                accept_vault_head(
                    &roster,
                    &DOC,
                    &a.author(),
                    &a.head(sequence, HEAD),
                    Some(last),
                    CAP
                ),
                Err(HeadRefused::NotNewer),
                "sequence {sequence} after {last}"
            );
        }
    }

    #[test]
    fn a_head_naming_a_copy_over_the_cap_is_refused() {
        let (_, a, _, roster) = account();
        let at_cap = VaultHead { size: CAP, ..HEAD };
        let over = VaultHead {
            size: CAP + 1,
            ..HEAD
        };
        assert!(
            accept_vault_head(&roster, &DOC, &a.author(), &a.head(1, at_cap), None, CAP).is_ok()
        );
        assert_eq!(
            accept_vault_head(&roster, &DOC, &a.author(), &a.head(1, over), None, CAP),
            Err(HeadRefused::CopyTooLarge)
        );
    }

    /// A head-kind statement whose payload isn't a head's shape is refused.
    #[test]
    fn a_head_statement_of_the_wrong_shape_is_refused() {
        let (_, a, _, roster) = account();
        for payload in [
            &[][..],
            &[0; VAULT_HEAD_PAYLOAD_BYTES - 1],
            &[0; VAULT_HEAD_PAYLOAD_BYTES + 1],
        ] {
            let bytes = Statement::sign(
                a.keys.sync_keys(),
                StatementKind::VaultHead,
                1,
                head_place(&DOC),
                payload,
            )
            .expect("signs");
            assert_eq!(
                accept_vault_head(&roster, &DOC, &a.author(), &bytes, None, CAP),
                Err(HeadRefused::NotAHead)
            );
        }
    }

    /// The known-answer device (signing seed `0x44`s), document id `0xd0`s,
    /// sequence 9, content hash `0xc0`s, size 4096. Computed independently
    /// of this crate.
    #[test]
    fn vault_head_known_answer() {
        let bytes = sign_vault_head(&kat_device_sync(), &DOC, 9, HEAD);
        assert_eq!(bytes, unhex(KAT_VAULT_HEAD));
    }

    const KAT_VAULT_HEAD: &str = concat!(
        "0101",
        "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48",
        "0000000000000009",
        "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
        "0000000000001000",
        "afe816a0026ba6cec6c149f26b917711d1061007764f22c103980896f7271c38",
        "f9e13cecb067728455586dc34dc764eecb3c9c1f3d2eb8a37016ab8b040bc30b",
    );
}
