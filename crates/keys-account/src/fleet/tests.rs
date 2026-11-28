//! Tests of the fleet document: the records' byte forms, sealing, and the
//! reader's rules.

use keys_pairing::{AccountKeys, DeviceKeys, FleetKey};

use super::read::FleetRefused;
use super::record::MAX_PEER_HEADS;
use super::*;
use crate::enrolment::DeviceEnrolment;
use crate::statement::{FleetKind, Placement, Statement, StatementKind};
use crate::test_support::{kat_account, kat_device_sync, unhex, usable_ed25519};

const DOC: [u8; 32] = [0xf1; 32];
const VAULT: VaultId = [0x7a; 16];
const VAULT_DOC: [u8; 32] = [0xd2; 32];

struct Device {
    keys: DeviceKeys,
    author: [u8; 32],
    enrolment: DeviceEnrolment,
}

struct Fleet {
    account: AccountKeys,
    key: FleetKey,
    alice: Device,
    bob: Device,
}

impl Fleet {
    fn new() -> Self {
        let (account, _) = AccountKeys::generate().expect("rng");
        let alice = Self::device(&account);
        let bob = Self::device(&account);
        Self {
            account,
            key: FleetKey::generate().expect("rng"),
            alice,
            bob,
        }
    }

    fn device(account: &AccountKeys) -> Device {
        let keys = DeviceKeys::generate().expect("rng");
        let author = usable_ed25519();
        let enrolment =
            DeviceEnrolment::sign(account, keys.public_keys(), usable_ed25519(), author)
                .expect("usable keys");
        Device {
            keys,
            author,
            enrolment,
        }
    }

    fn identity(&self) -> [u8; 32] {
        self.account.identity_public_key()
    }

    /// `writer`'s record at `sequence`, as an entry under `author`.
    fn entry(
        &self,
        writer: &Device,
        author: [u8; 32],
        sequence: u64,
        record: &FleetRecord,
    ) -> FleetEntry {
        let sealed =
            seal_record(&self.key, &DOC, writer.keys.sync_keys(), sequence, record).expect("seals");
        FleetEntry {
            author,
            key: sealed.key.to_vec(),
            value: sealed.value,
        }
    }

    /// `writer`'s record under its own author.
    fn own(&self, writer: &Device, sequence: u64, record: &FleetRecord) -> FleetEntry {
        self.entry(writer, writer.author, sequence, record)
    }

    /// Both devices' enrolments, each written by its own device.
    fn enrolled(&self) -> Vec<FleetEntry> {
        vec![
            self.own(
                &self.alice,
                1,
                &FleetRecord::Enrolment(self.alice.enrolment),
            ),
            self.own(&self.bob, 1, &FleetRecord::Enrolment(self.bob.enrolment)),
        ]
    }

    fn read(&self, entries: impl IntoIterator<Item = FleetEntry>) -> FleetRead {
        read_fleet(&self.identity(), &self.key, &DOC, entries)
    }

    fn epoch(&self, epoch: u64, doc: [u8; 32]) -> FleetRecord {
        FleetRecord::VaultEpoch(VaultEpoch::sign(&self.account, &VAULT, &doc, epoch))
    }
}

fn name(device: &Device, name: &str) -> FleetRecord {
    FleetRecord::DeviceName(DeviceName {
        device_id: device.enrolment.device_id(),
        name: name.to_owned(),
    })
}

fn info(last_seen: u64) -> FleetRecord {
    FleetRecord::DeviceInfo(DeviceInfo {
        platform: "macos".to_owned(),
        paired_at: 1,
        last_seen,
    })
}

/// The reasons entries were refused, in a fixed order (entries are read in
/// the order of their bytes, which the tests don't fix).
fn reasons(read: &FleetRead) -> Vec<FleetRefused> {
    let mut reasons: Vec<FleetRefused> = read.refused.iter().map(|r| r.reason).collect();
    reasons.sort_by_key(|reason| format!("{reason:?}"));
    reasons
}

fn device_ids(read: &FleetRead) -> Vec<DeviceId> {
    read.view
        .devices
        .iter()
        .map(|d| d.enrolment.device_id())
        .collect()
}

fn sorted(mut ids: Vec<DeviceId>) -> Vec<DeviceId> {
    ids.sort_unstable();
    ids
}

#[test]
fn an_honest_fleet_reads_as_written() {
    let fleet = Fleet::new();
    let mut entries = fleet.enrolled();
    entries.push(fleet.own(&fleet.alice, 2, &name(&fleet.alice, "Alice's Mac")));
    entries.push(fleet.own(&fleet.alice, 3, &info(77)));
    entries.push(fleet.own(&fleet.alice, 4, &fleet.epoch(1, VAULT_DOC)));
    entries.push(fleet.own(
        &fleet.alice,
        5,
        &FleetRecord::VaultLook(VaultLook {
            vault_id: VAULT,
            name: "Family".to_owned(),
            icon: "house.fill".to_owned(),
            colour: [0x12, 0x34, 0x56],
        }),
    ));
    let holding = Holding {
        vault_id: VAULT,
        epoch: 1,
        has_secrets: true,
        own_head: Some([0xaa; 32]),
        peer_heads: vec![(fleet.bob.enrolment.device_id(), [0xbb; 32])],
    };
    entries.push(fleet.own(&fleet.alice, 6, &FleetRecord::Holding(holding.clone())));
    entries.push(fleet.own(
        &fleet.bob,
        7,
        &FleetRecord::Setting(Setting {
            name: "cellular-cap".to_owned(),
            value: b"on".to_vec(),
        }),
    ));
    let read = fleet.read(entries.clone());
    assert!(reasons(&read).is_empty(), "{:?}", read.refused);
    assert_eq!(read.kept.len(), entries.len());
    let view = &read.view;
    assert_eq!(
        device_ids(&read),
        sorted(vec![
            fleet.alice.enrolment.device_id(),
            fleet.bob.enrolment.device_id()
        ])
    );
    let alice = view
        .devices
        .iter()
        .find(|d| d.enrolment == fleet.alice.enrolment)
        .expect("alice");
    assert_eq!(alice.name.as_deref(), Some("Alice's Mac"));
    assert_eq!(alice.info.as_ref().map(|i| i.last_seen), Some(77));
    let [vault] = view.vaults.as_slice() else {
        panic!("one vault: {:?}", view.vaults)
    };
    assert_eq!((vault.epoch, vault.doc_id), (1, VAULT_DOC));
    assert_eq!(vault.look.as_ref().map(|l| l.name.as_str()), Some("Family"));
    assert_eq!(
        vault.holdings,
        vec![(fleet.alice.enrolment.device_id(), holding)]
    );
    assert_eq!(
        view.settings,
        vec![FleetSetting {
            name: "cellular-cap".to_owned(),
            value: b"on".to_vec()
        }]
    );
    assert_eq!(view.removed, Vec::<DeviceId>::new());
    assert!(
        view.roster
            .device_by_author(&fleet.bob.author)
            .is_some_and(|d| *d == fleet.bob.enrolment)
    );
}

#[test]
fn entries_not_sealed_for_their_place_under_this_fleet_key_are_refused() {
    let fleet = Fleet::new();
    let genuine = fleet.own(
        &fleet.alice,
        1,
        &FleetRecord::Enrolment(fleet.alice.enrolment),
    );
    // Under another fleet key (a stranger with the ticket, or another
    // account's fleet).
    let stranger = Fleet::new();
    let foreign = stranger.own(
        &stranger.alice,
        1,
        &FleetRecord::Enrolment(stranger.alice.enrolment),
    );
    // Moved to another entry key.
    let moved = FleetEntry {
        key: fleet.key.entry_key(b"elsewhere").to_vec(),
        ..genuine.clone()
    };
    // Plain bytes.
    let junk = FleetEntry {
        value: b"junk".to_vec(),
        ..genuine.clone()
    };
    let read = fleet.read([foreign, moved, junk]);
    assert_eq!(reasons(&read), [FleetRefused::NotSealed; 3]);
    assert!(read.view.devices.is_empty() && read.kept.is_empty());
    // The same entry read in another document doesn't open either.
    let other_doc = read_fleet(&fleet.identity(), &fleet.key, &[0x0d; 32], [genuine]);
    assert_eq!(reasons(&other_doc), [FleetRefused::NotSealed]);
}

#[test]
fn a_record_sealed_into_another_slot_is_misplaced() {
    let fleet = Fleet::new();
    // Signed and sealed honestly for an entry key, but not its own slot's.
    let key = fleet.key.entry_key(b"not the slot");
    let record = FleetRecord::Enrolment(fleet.alice.enrolment);
    let statement = Statement::sign(
        fleet.alice.keys.sync_keys(),
        StatementKind::Fleet(FleetKind::Enrolment),
        1,
        Placement {
            doc_id: &DOC,
            entry_key: &key,
        },
        &record.encode().expect("encodes"),
    )
    .expect("signs");
    let entry = FleetEntry {
        author: fleet.alice.author,
        key: key.to_vec(),
        value: fleet.key.seal(&[&DOC, &key], &statement).expect("rng"),
    };
    let wrong_length = FleetEntry {
        key: vec![1, 2, 3],
        ..entry.clone()
    };
    let read = fleet.read([entry, wrong_length]);
    assert_eq!(
        reasons(&read),
        [FleetRefused::Misplaced, FleetRefused::Misplaced]
    );
}

#[test]
fn a_devices_word_counts_only_from_a_current_device_under_its_own_author() {
    let fleet = Fleet::new();
    let outsider = DeviceKeys::generate().expect("rng");
    let outsider = Device {
        author: usable_ed25519(),
        enrolment: fleet.alice.enrolment,
        keys: outsider,
    };
    let mut entries = fleet.enrolled();
    // Alice's statement written under Bob's author (a thief with Bob's
    // store and the fleet key).
    entries.push(fleet.entry(
        &fleet.alice,
        fleet.bob.author,
        2,
        &name(&fleet.alice, "Stolen"),
    ));
    // A key that is no device's, under Alice's author.
    entries.push(fleet.entry(&outsider, fleet.alice.author, 2, &info(1)));
    let read = fleet.read(entries);
    assert_eq!(reasons(&read), [FleetRefused::Unbound; 2]);
    assert!(
        read.view
            .devices
            .iter()
            .all(|d| d.name.is_none() && d.info.is_none())
    );
}

#[test]
fn the_accounts_records_count_whoever_writes_them() {
    let fleet = Fleet::new();
    // Bob copies Alice's enrolment and the vault's epoch record, under his
    // own author.
    let entries = vec![
        fleet.own(
            &fleet.bob,
            1,
            &FleetRecord::Enrolment(fleet.alice.enrolment),
        ),
        fleet.own(&fleet.bob, 2, &fleet.epoch(1, VAULT_DOC)),
    ];
    let read = fleet.read(entries);
    assert!(reasons(&read).is_empty(), "{:?}", read.refused);
    assert_eq!(device_ids(&read), [fleet.alice.enrolment.device_id()]);
    assert_eq!(read.view.vaults.len(), 1);
}

#[test]
fn account_records_not_signed_by_this_account_are_refused() {
    let fleet = Fleet::new();
    let other = Fleet::new();
    let entries = vec![
        fleet.own(
            &fleet.alice,
            1,
            &FleetRecord::Enrolment(other.alice.enrolment),
        ),
        fleet.own(
            &fleet.alice,
            2,
            &FleetRecord::Tombstone(Tombstone::sign(
                &other.account,
                &fleet.alice.enrolment.device_id(),
            )),
        ),
        fleet.own(
            &fleet.alice,
            3,
            &FleetRecord::VaultEpoch(VaultEpoch::sign(&other.account, &VAULT, &VAULT_DOC, 1)),
        ),
    ];
    let read = fleet.read(entries);
    assert_eq!(
        reasons(&read),
        [
            FleetRefused::Record(RecordError::NotAccountSigned),
            FleetRefused::Record(RecordError::NotAccountSigned),
            FleetRefused::Record(RecordError::NotEnrolled),
        ]
    );
}

#[test]
fn a_tombstone_outranks_every_enrolment_and_word_of_its_device() {
    let fleet = Fleet::new();
    let bob = fleet.bob.enrolment.device_id();
    let mut entries = fleet.enrolled();
    entries.push(fleet.own(
        &fleet.alice,
        5,
        &FleetRecord::Tombstone(Tombstone::sign(&fleet.account, &bob)),
    ));
    // Bob, removed, writes his enrolment back with a later sequence, and
    // goes on writing.
    entries.push(fleet.own(&fleet.bob, 9, &FleetRecord::Enrolment(fleet.bob.enrolment)));
    entries.push(fleet.own(&fleet.bob, 10, &name(&fleet.alice, "Bob was here")));
    entries.push(fleet.own(&fleet.bob, 11, &fleet.epoch(1, VAULT_DOC)));
    let read = fleet.read(entries);
    assert_eq!(device_ids(&read), [fleet.alice.enrolment.device_id()]);
    assert_eq!(read.view.removed, [bob]);
    assert!(read.view.devices[0].name.is_none());
    assert!(
        read.view
            .roster
            .device_by_author(&fleet.bob.author)
            .is_none()
    );
    // The account's epoch record still counts, whoever copied it.
    assert_eq!(read.view.vaults.len(), 1);
    assert_eq!(reasons(&read), [FleetRefused::Removed; 3]);
}

#[test]
fn clashing_enrolments_are_both_refused() {
    let fleet = Fleet::new();
    // Another enrolment of Bob's keys, binding a different author.
    let again = DeviceEnrolment::sign(
        &fleet.account,
        fleet.bob.keys.public_keys(),
        usable_ed25519(),
        usable_ed25519(),
    )
    .expect("usable keys");
    // And a third device claiming Alice's author.
    let carol = DeviceKeys::generate().expect("rng");
    let squatter = DeviceEnrolment::sign(
        &fleet.account,
        carol.public_keys(),
        usable_ed25519(),
        fleet.alice.author,
    )
    .expect("usable keys");
    let mut entries = fleet.enrolled();
    entries.push(fleet.own(&fleet.bob, 2, &FleetRecord::Enrolment(again)));
    entries.push(fleet.own(&fleet.alice, 2, &FleetRecord::Enrolment(squatter)));
    let read = fleet.read(entries);
    assert_eq!(read.view.devices, Vec::<FleetDevice>::new());
    assert_eq!(reasons(&read), [FleetRefused::Clashing; 4]);
}

#[test]
fn the_newest_statement_per_signer_and_slot_counts_and_is_kept() {
    let fleet = Fleet::new();
    let mut entries = fleet.enrolled();
    let older = fleet.own(&fleet.alice, 2, &info(10));
    let newer = fleet.own(&fleet.alice, 3, &info(20));
    entries.push(newer.clone());
    let first = fleet.read(entries);
    assert!(first.kept.contains(&newer));
    // The newer entry is overwritten with the older one (same slot, same
    // author): a reader that kept the newer one isn't moved back.
    let mut second_input = first.kept.clone();
    second_input.push(older.clone());
    let second = fleet.read(second_input);
    let alice = &second
        .view
        .devices
        .iter()
        .find(|d| d.enrolment == fleet.alice.enrolment);
    assert_eq!(
        alice.and_then(|d| d.info.as_ref()).map(|i| i.last_seen),
        Some(20)
    );
    assert!(second.kept.contains(&newer) && !second.kept.contains(&older));
    assert_eq!(reasons(&second), Vec::<FleetRefused>::new());
}

#[test]
fn a_vault_is_at_its_highest_epoch_and_the_entry_carrying_it_is_kept() {
    let fleet = Fleet::new();
    let mut entries = fleet.enrolled();
    let epoch_two = fleet.own(&fleet.alice, 5, &fleet.epoch(2, [0xe2; 32]));
    entries.push(epoch_two.clone());
    // Alice's slot then gets an older epoch at a later sequence (a thief
    // with her keys putting back an old record), and Bob writes epoch 1.
    entries.push(fleet.own(&fleet.alice, 6, &fleet.epoch(1, VAULT_DOC)));
    entries.push(fleet.own(&fleet.bob, 4, &fleet.epoch(1, VAULT_DOC)));
    let read = fleet.read(entries);
    assert_eq!(read.view.vaults[0].epoch, 2);
    assert_eq!(read.view.vaults[0].doc_id, [0xe2; 32]);
    assert!(read.kept.contains(&epoch_two));
    // And reading only what was kept, without the document, still says 2.
    let again = fleet.read(read.kept.clone());
    assert_eq!(again.view.vaults[0].epoch, 2);
}

#[test]
fn the_latest_name_wins_and_every_reader_agrees() {
    let fleet = Fleet::new();
    let mut entries = fleet.enrolled();
    entries.push(fleet.own(&fleet.alice, 5, &name(&fleet.alice, "Older")));
    entries.push(fleet.own(&fleet.bob, 8, &name(&fleet.alice, "Newer")));
    let read = fleet.read(entries.clone());
    let alice = |read: &FleetRead| {
        read.view
            .devices
            .iter()
            .find(|d| d.enrolment == fleet.alice.enrolment)
            .and_then(|d| d.name.clone())
    };
    assert_eq!(alice(&read).as_deref(), Some("Newer"));
    // A tie in sequence goes to the higher signer id, in any order.
    let mut tied = fleet.enrolled();
    tied.push(fleet.own(&fleet.alice, 8, &name(&fleet.alice, "By Alice")));
    tied.push(fleet.own(&fleet.bob, 8, &name(&fleet.alice, "By Bob")));
    let higher = if fleet.alice.enrolment.device_id() > fleet.bob.enrolment.device_id() {
        "By Alice"
    } else {
        "By Bob"
    };
    let forwards = fleet.read(tied.clone());
    tied.reverse();
    let backwards = fleet.read(tied);
    assert_eq!(alice(&forwards).as_deref(), Some(higher));
    assert_eq!(alice(&backwards).as_deref(), Some(higher));
}

#[test]
fn a_holding_counts_only_from_its_device_and_never_lists_itself() {
    let fleet = Fleet::new();
    let alice = fleet.alice.enrolment.device_id();
    let holding = |peers: Vec<(DeviceId, HeadHash)>| {
        FleetRecord::Holding(Holding {
            vault_id: VAULT,
            epoch: 1,
            has_secrets: false,
            own_head: None,
            peer_heads: peers,
        })
    };
    let mut entries = fleet.enrolled();
    entries.push(fleet.own(&fleet.alice, 2, &fleet.epoch(1, VAULT_DOC)));
    entries.push(fleet.own(&fleet.bob, 3, &holding(vec![])));
    entries.push(fleet.own(&fleet.alice, 3, &holding(vec![(alice, [1; 32])])));
    let read = fleet.read(entries);
    assert_eq!(reasons(&read), [FleetRefused::SelfPeer]);
    assert_eq!(
        read.view.vaults[0]
            .holdings
            .iter()
            .map(|(device, _)| *device)
            .collect::<Vec<_>>(),
        [fleet.bob.enrolment.device_id()]
    );
}

#[test]
fn every_record_round_trips_through_its_byte_form() {
    let account = kat_account();
    let identity = account.identity_public_key();
    let device = usable_ed25519();
    let records = [
        FleetRecord::Enrolment(
            DeviceEnrolment::sign(
                &account,
                DeviceKeys::generate().expect("rng").public_keys(),
                usable_ed25519(),
                usable_ed25519(),
            )
            .expect("usable keys"),
        ),
        FleetRecord::Tombstone(Tombstone::sign(&account, &device)),
        FleetRecord::VaultEpoch(VaultEpoch::sign(&account, &VAULT, &VAULT_DOC, 3)),
        info(5),
        FleetRecord::DeviceName(DeviceName {
            device_id: device,
            name: "Jeff's iPad 🍎".to_owned(),
        }),
        FleetRecord::VaultLook(VaultLook {
            vault_id: VAULT,
            name: "Work".to_owned(),
            icon: "briefcase".to_owned(),
            colour: [1, 2, 3],
        }),
        FleetRecord::Holding(Holding {
            vault_id: VAULT,
            epoch: 3,
            has_secrets: true,
            own_head: Some([9; 32]),
            peer_heads: (0..MAX_PEER_HEADS)
                .map(|i| ([u8::try_from(i).expect("small"); 32], [7; 32]))
                .collect(),
        }),
        FleetRecord::Setting(Setting {
            name: "retention".to_owned(),
            value: vec![0; record::MAX_SETTING_VALUE_BYTES],
        }),
    ];
    for record in records {
        let bytes = record.encode().expect("encodes");
        assert!(bytes.len() <= crate::statement::MAX_PAYLOAD_BYTES);
        assert_eq!(
            FleetRecord::decode(record.kind(), &bytes, &identity),
            Ok(record.clone())
        );
        // Nothing may follow a record, and none reads as another kind's
        // with the same bytes.
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(FleetRecord::decode(record.kind(), &longer, &identity).is_err());
        for kind in FleetKind::ALL {
            if kind != record.kind() {
                assert_ne!(
                    FleetRecord::decode(kind, &bytes, &identity).ok(),
                    Some(record.clone())
                );
            }
        }
    }
}

#[test]
fn only_canonical_records_are_written_or_read() {
    let identity = kat_account().identity_public_key();
    let invalid = [
        info(0).clone_with_platform("MacOS"),
        info(0).clone_with_platform(""),
        info(0).clone_with_platform(&"a".repeat(record::MAX_PLATFORM_BYTES + 1)),
        FleetRecord::DeviceName(DeviceName {
            device_id: [1; 32],
            name: " padded ".to_owned(),
        }),
        FleetRecord::DeviceName(DeviceName {
            device_id: [1; 32],
            name: "\u{202e}reversed".to_owned(),
        }),
        FleetRecord::DeviceName(DeviceName {
            device_id: [1; 32],
            name: String::new(),
        }),
        FleetRecord::Holding(Holding {
            vault_id: VAULT,
            epoch: 1,
            has_secrets: false,
            own_head: None,
            peer_heads: vec![([2; 32], [0; 32]), ([1; 32], [0; 32])],
        }),
        FleetRecord::Holding(Holding {
            vault_id: VAULT,
            epoch: 1,
            has_secrets: false,
            own_head: None,
            peer_heads: (0..=MAX_PEER_HEADS)
                .map(|i| ([u8::try_from(i).expect("small"); 32], [0; 32]))
                .collect(),
        }),
        FleetRecord::Setting(Setting {
            name: "x".to_owned(),
            value: vec![0; record::MAX_SETTING_VALUE_BYTES + 1],
        }),
    ];
    for record in invalid {
        assert_eq!(record.encode(), Err(RecordError::Invalid), "{record:?}");
    }
    // Read side: an unknown holding flag, a name that isn't as the
    // sanitiser leaves it, and peers out of order.
    let mut holding = FleetRecord::Holding(Holding {
        vault_id: VAULT,
        epoch: 1,
        has_secrets: false,
        own_head: None,
        peer_heads: vec![],
    })
    .encode()
    .expect("encodes");
    holding[16 + 8] |= 0x80;
    assert_eq!(
        FleetRecord::decode(FleetKind::Holding, &holding, &identity),
        Err(RecordError::Malformed)
    );
    let mut padded = vec![1; 32];
    padded.extend_from_slice(&3u16.to_be_bytes());
    padded.extend_from_slice(b" a ");
    assert_eq!(
        FleetRecord::decode(FleetKind::DeviceName, &padded, &identity),
        Err(RecordError::Malformed)
    );
    let mut unordered = vec![0x7a; 16];
    unordered.extend_from_slice(&1u64.to_be_bytes());
    unordered.push(0);
    unordered.push(2);
    unordered.extend_from_slice(&[[2u8; 32], [0; 32], [1; 32], [0; 32]].concat());
    assert_eq!(
        FleetRecord::decode(FleetKind::Holding, &unordered, &identity),
        Err(RecordError::Malformed)
    );
}

trait WithPlatform {
    fn clone_with_platform(&self, platform: &str) -> FleetRecord;
}

impl WithPlatform for FleetRecord {
    fn clone_with_platform(&self, platform: &str) -> FleetRecord {
        let FleetRecord::DeviceInfo(info) = self else {
            unreachable!("only device info has a platform")
        };
        FleetRecord::DeviceInfo(DeviceInfo {
            platform: platform.to_owned(),
            ..info.clone()
        })
    }
}

#[test]
fn last_seen_is_due_hourly() {
    let hour = LAST_SEEN_INTERVAL_MICROS;
    assert!(last_seen_due(None, 0));
    assert!(!last_seen_due(Some(10), 10 + hour - 1));
    assert!(last_seen_due(Some(10), 10 + hour));
    assert!(last_seen_due(Some(10), 9));
}

#[test]
fn only_entries_small_enough_to_be_records_are_fetched() {
    assert!(fleet_entry_to_fetch(MAX_SEALED_BYTES as u64));
    assert!(!fleet_entry_to_fetch(MAX_SEALED_BYTES as u64 + 1));
}

/// The account-signed records' byte forms, recomputed independently from
/// the formats (Ed25519 signatures are deterministic).
#[test]
fn account_records_known_answer() {
    let account = kat_account();
    let device = kat_device_sync().signing_public_key();
    let tombstone = FleetRecord::Tombstone(Tombstone::sign(&account, &device))
        .encode()
        .expect("encodes");
    assert_eq!(tombstone, unhex(KAT_TOMBSTONE));
    let epoch = FleetRecord::VaultEpoch(VaultEpoch::sign(&account, &VAULT, &VAULT_DOC, 3))
        .encode()
        .expect("encodes");
    assert_eq!(epoch, unhex(KAT_VAULT_EPOCH));
}

const KAT_TOMBSTONE: &str = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48bb2c196262a58e767280f73aca41a1de81fc9513265eaacf47aede3b0e8b49511093086508b34ae49cb2f527c5ee154005056d42abe262ccc01b074a0031640b";
const KAT_VAULT_EPOCH: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7ad2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d200000000000000035405d824395365f6393543a7ae7a66a0435a96906f857bf4978a327b7917157aec16c8f5bf8a1af3f3102090094a5b7e4ff68ab14530157ab718f70dfee8ae03";
