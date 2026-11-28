//! Fuzz target for reading the account's fleet document: entries anyone
//! holding the document's write ticket can write, under any author, and
//! anyone holding the fleet key can seal and sign with keys of their own.
//!
//! A panic is a bug. So is any change to what the account looks like, or to
//! how much a reader keeps. The fixture is an account with two current
//! devices and a removed one, and a genuine set of records; the fuzzer adds
//! one entry, under an author it picks (a current device's, the removed
//! device's, or no device's), whose value is one of:
//! - its own bytes, raw or sealed under the real fleet key at an entry key
//!   it picks (a genuine slot's, or one of its own naming);
//! - its bytes as a record of a kind it picks, in a statement signed by a
//!   key that is no device's or by the removed device, at a sequence it
//!   picks, sealed in that record's own slot;
//! - one of the account's genuine records, copied the same way.
//!
//! Without a current device's or the account's signing key it can't make a
//! record that counts, and a copy of the account's records counts once, so
//! the view and the number of entries kept must stay the genuine ones, and
//! what is kept must read back as the same view. It also feeds arbitrary
//! bytes to every record parser: whatever parses must write back as the
//! same bytes, so each record has one byte form.

#![no_main]

use std::sync::OnceLock;

use keys_account::DeviceEnrolment;
use keys_account::fleet::{
    DeviceInfo, DeviceName, FleetEntry, FleetRead, FleetRecord, Setting, Tombstone, VaultEpoch,
    read_fleet, seal_record,
};
use keys_account::statement::{FleetKind, Placement, Statement, StatementKind};
use keys_pairing::{AccountKeys, DeviceKeys, FleetKey};
use libfuzzer_sys::fuzz_target;

/// Seed for the scripted random stream, so the account, the devices, the
/// fleet key and every sealed value are the same on every run.
const SEED: &[u8] = b"keys-account fuzz: fleet";
const DOC: [u8; 32] = [0xf1; 32];
const VAULT: [u8; 16] = [0x7a; 16];
/// The fuzzer's choices that come before its bytes.
const MODES: u8 = 5;

struct Fixture {
    identity: [u8; 32],
    fleet_key: FleetKey,
    /// Alice's author, Bob's, Carol's (removed) and one that is no device's.
    authors: [[u8; 32]; 4],
    /// Carol, removed, and a key that is no device's.
    signers: [DeviceKeys; 2],
    genuine: Vec<FleetEntry>,
    /// The genuine entries' keys, for the fuzzer to write over.
    keys: Vec<Vec<u8>>,
    /// The account's records, for the fuzzer to copy.
    account_records: Vec<FleetRecord>,
    read: FleetRead,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn usable_key() -> [u8; 32] {
    DeviceKeys::generate()
        .expect("scripted random")
        .public_keys()
        .signing
}

fn entry(author: [u8; 32], sealed: keys_account::fleet::SealedRecord) -> FleetEntry {
    FleetEntry {
        author,
        key: sealed.key.to_vec(),
        value: sealed.value,
    }
}

fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| {
        keys_pairing::script_random_for_fuzzing(SEED);
        let (account, _) = AccountKeys::generate().expect("scripted random");
        let fleet_key = FleetKey::generate().expect("scripted random");
        let alice = DeviceKeys::generate().expect("scripted random");
        let bob = DeviceKeys::generate().expect("scripted random");
        let carol = DeviceKeys::generate().expect("scripted random");
        let stranger = DeviceKeys::generate().expect("scripted random");
        let authors = [usable_key(), usable_key(), usable_key(), usable_key()];
        let enrol = |device: &DeviceKeys, author| {
            FleetRecord::Enrolment(
                DeviceEnrolment::sign(&account, device.public_keys(), usable_key(), author)
                    .expect("usable keys"),
            )
        };
        let account_records = vec![
            enrol(&alice, authors[0]),
            enrol(&bob, authors[1]),
            enrol(&carol, authors[2]),
            FleetRecord::Tombstone(
                Tombstone::sign(&account, &carol.public_keys().signing).expect("usable id"),
            ),
            FleetRecord::VaultEpoch(VaultEpoch::sign(&account, &VAULT, &[0xd2; 32], 4)),
        ];
        let write = |device: &DeviceKeys, author: [u8; 32], sequence, record: &FleetRecord| {
            entry(
                author,
                seal_record(&fleet_key, &DOC, device.sync_keys(), sequence, record).expect("seals"),
            )
        };
        let genuine = vec![
            write(&alice, authors[0], 1, &account_records[0]),
            write(&bob, authors[1], 1, &account_records[1]),
            write(&carol, authors[2], 1, &account_records[2]),
            write(&alice, authors[0], 2, &account_records[3]),
            write(&alice, authors[0], 3, &account_records[4]),
            write(
                &alice,
                authors[0],
                4,
                &FleetRecord::DeviceName(DeviceName {
                    device_id: alice.public_keys().signing,
                    name: "Alice".to_owned(),
                }),
            ),
            write(
                &bob,
                authors[1],
                2,
                &FleetRecord::DeviceInfo(DeviceInfo {
                    platform: "android".to_owned(),
                    paired_at: 1,
                    last_seen: 2,
                }),
            ),
            write(
                &bob,
                authors[1],
                3,
                &FleetRecord::Setting(Setting {
                    name: "cellular-cap".to_owned(),
                    value: b"on".to_vec(),
                }),
            ),
        ];
        let identity = account.identity_public_key();
        let read = read_fleet(&identity, &fleet_key, &DOC, genuine.clone());
        assert_eq!(read.view.devices.len(), 2, "Alice and Bob are current");
        assert_eq!(read.view.removed.len(), 1, "Carol is removed");
        Fixture {
            identity,
            keys: genuine.iter().map(|e| e.key.clone()).collect(),
            fleet_key,
            authors,
            signers: [carol, stranger],
            genuine,
            account_records,
            read,
        }
    })
}

/// Everything a read shows, the roster included.
fn same_view(a: &FleetRead, b: &FleetRead) -> bool {
    let (a, b) = (&a.view, &b.view);
    a.devices == b.devices
        && a.removed == b.removed
        && a.vaults == b.vaults
        && a.settings == b.settings
        && a.roster.devices() == b.roster.devices()
}

/// `payload` as a record of `kind` signed by `signer` at `sequence`, sealed
/// in the record's own slot if it is one, else at `key`.
fn signed(
    fixture: &Fixture,
    signer: &DeviceKeys,
    kind: FleetKind,
    sequence: u64,
    payload: &[u8],
    key: Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    if let Ok(record) = FleetRecord::decode(kind, payload, &fixture.identity)
        && let Ok(sealed) = seal_record(
            &fixture.fleet_key,
            &DOC,
            signer.sync_keys(),
            sequence,
            &record,
        )
    {
        return (sealed.key.to_vec(), sealed.value);
    }
    let Ok(statement) = Statement::sign(
        signer.sync_keys(),
        StatementKind::Fleet(kind),
        sequence,
        Placement {
            doc_id: &DOC,
            entry_key: &key,
        },
        payload,
    ) else {
        return (key, payload.to_vec());
    };
    let value = fixture
        .fleet_key
        .seal(&[&DOC, &key], &statement)
        .expect("scripted random");
    (key, value)
}

/// The fuzzer's choices: a mode, an author, an entry key, a record kind, a
/// signer and a sequence, each from bytes of its own.
const CHOICE_BYTES: usize = 13;

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let Some((choices, rest)) = data.split_first_chunk::<CHOICE_BYTES>() else {
        return;
    };
    let [mode, author, key, choice, signer, sequence @ ..] = *choices;
    let sequence = u64::from_be_bytes(sequence);
    let kind = FleetKind::ALL[usize::from(choice) % FleetKind::ALL.len()];
    let mode = mode % MODES;
    if mode == 4 {
        // Every parser: what parses writes back as the same bytes.
        if let Ok(record) = FleetRecord::decode(kind, rest, &fixture.identity) {
            assert_eq!(record.kind(), kind);
            assert_eq!(
                record.encode().as_deref(),
                Ok(rest),
                "a record has more than one byte form"
            );
        }
        return;
    }
    let author = fixture.authors[usize::from(author) % fixture.authors.len()];
    // A genuine entry's key, or one of the fuzzer's own naming.
    let chosen_key = fixture
        .keys
        .get(usize::from(key))
        .cloned()
        .unwrap_or_else(|| fixture.fleet_key.entry_key(&[key]).to_vec());
    let signer = &fixture.signers[usize::from(signer) % fixture.signers.len()];
    let (key, value) = match mode {
        0 => (chosen_key, rest.to_vec()),
        // Sealed under the real fleet key for its place, as a holder of the
        // key could.
        1 => {
            let value = fixture
                .fleet_key
                .seal(&[&DOC, &chosen_key], rest)
                .expect("scripted random");
            (chosen_key, value)
        }
        2 => signed(fixture, signer, kind, sequence, rest, chosen_key),
        _ => {
            // A copy of one of the account's own records.
            let record =
                &fixture.account_records[usize::from(choice) % fixture.account_records.len()];
            let payload = record.encode().expect("genuine records encode");
            signed(
                fixture,
                signer,
                record.kind(),
                sequence,
                &payload,
                chosen_key,
            )
        }
    };
    let mut entries = fixture.genuine.clone();
    entries.push(FleetEntry { author, key, value });
    let read = read_fleet(&fixture.identity, &fixture.fleet_key, &DOC, entries);
    assert!(
        same_view(&read, &fixture.read),
        "an entry no current device or the account signed changed the account"
    );
    assert_eq!(
        read.kept.len(),
        fixture.read.kept.len(),
        "an entry no current device or the account signed is kept"
    );
    let again = read_fleet(
        &fixture.identity,
        &fixture.fleet_key,
        &DOC,
        read.kept.clone(),
    );
    assert!(
        same_view(&again, &read),
        "what was kept doesn't read back as what was read"
    );
});
