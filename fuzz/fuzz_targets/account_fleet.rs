//! Fuzz target for reading the account's fleet document: entries anyone
//! holding the document's write ticket can write, under any author, and
//! anyone holding the fleet key can seal.
//!
//! A panic is a bug. So is any change to what the account looks like. The
//! fixture is an account with two enrolled devices and a genuine set of
//! records; the fuzzer adds one entry, under an author it picks (either
//! device's, or one that is no device's) and an entry key it picks (a real
//! slot's, or its own), whose value is either its own bytes or its bytes
//! sealed under the real fleet key, as a removed device or anyone else
//! holding the key could. Without a device's or the account's signing key it
//! can't make a record that counts, so the view must stay the genuine one.
//! It also feeds arbitrary bytes to every record parser: whatever parses must
//! write back as the same bytes, so each record has one byte form.

#![no_main]

use std::sync::OnceLock;

use keys_account::DeviceEnrolment;
use keys_account::fleet::{
    DeviceInfo, DeviceName, FleetEntry, FleetRecord, FleetView, Setting, VaultEpoch, read_fleet,
    seal_record,
};
use keys_account::statement::FleetKind;
use keys_pairing::{AccountKeys, DeviceKeys, FleetKey};
use libfuzzer_sys::fuzz_target;

/// Seed for the scripted random stream, so the account, the devices, the
/// fleet key and every sealed value are the same on every run.
const SEED: &[u8] = b"keys-account fuzz: fleet";
const DOC: [u8; 32] = [0xf1; 32];
const VAULT: [u8; 16] = [0x7a; 16];

struct Fixture {
    identity: [u8; 32],
    fleet_key: FleetKey,
    /// Alice's author, Bob's, and one that is no device's.
    authors: [[u8; 32]; 3],
    genuine: Vec<FleetEntry>,
    /// The genuine entries' keys, for the fuzzer to write over.
    keys: Vec<Vec<u8>>,
    view: FleetView,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn usable_key() -> [u8; 32] {
    DeviceKeys::generate()
        .expect("scripted random")
        .public_keys()
        .signing
}

fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| {
        keys_pairing::script_random_for_fuzzing(SEED);
        let (account, _) = AccountKeys::generate().expect("scripted random");
        let fleet_key = FleetKey::generate().expect("scripted random");
        let alice = DeviceKeys::generate().expect("scripted random");
        let bob = DeviceKeys::generate().expect("scripted random");
        let authors = [usable_key(), usable_key(), usable_key()];
        let enrol = |device: &DeviceKeys, author| {
            DeviceEnrolment::sign(&account, device.public_keys(), usable_key(), author)
                .expect("usable keys")
        };
        let write = |device: &DeviceKeys, author: [u8; 32], sequence, record: FleetRecord| {
            let sealed = seal_record(&fleet_key, &DOC, device.sync_keys(), sequence, &record)
                .expect("seals");
            FleetEntry {
                author,
                key: sealed.key.to_vec(),
                value: sealed.value,
            }
        };
        let genuine = vec![
            write(
                &alice,
                authors[0],
                1,
                FleetRecord::Enrolment(enrol(&alice, authors[0])),
            ),
            write(
                &bob,
                authors[1],
                1,
                FleetRecord::Enrolment(enrol(&bob, authors[1])),
            ),
            write(
                &alice,
                authors[0],
                2,
                FleetRecord::DeviceName(DeviceName {
                    device_id: alice.public_keys().signing,
                    name: "Alice".to_owned(),
                }),
            ),
            write(
                &bob,
                authors[1],
                2,
                FleetRecord::DeviceInfo(DeviceInfo {
                    platform: "android".to_owned(),
                    paired_at: 1,
                    last_seen: 2,
                }),
            ),
            write(
                &alice,
                authors[0],
                3,
                FleetRecord::VaultEpoch(VaultEpoch::sign(&account, &VAULT, &[0xd2; 32], 4)),
            ),
            write(
                &bob,
                authors[1],
                3,
                FleetRecord::Setting(Setting {
                    name: "cellular-cap".to_owned(),
                    value: b"on".to_vec(),
                }),
            ),
        ];
        let identity = account.identity_public_key();
        let view = read_fleet(&identity, &fleet_key, &DOC, genuine.clone()).view;
        assert_eq!(view.devices.len(), 2, "the fixture's devices are enrolled");
        Fixture {
            identity,
            keys: genuine.iter().map(|e| e.key.clone()).collect(),
            fleet_key,
            authors,
            genuine,
            view,
        }
    })
}

fn same_view(a: &FleetView, b: &FleetView) -> bool {
    a.devices == b.devices
        && a.removed == b.removed
        && a.vaults == b.vaults
        && a.settings == b.settings
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let Some((&[mode, author, key], rest)) = data.split_first_chunk::<3>() else {
        return;
    };
    if mode % 3 == 2 {
        // Every parser: what parses writes back as the same bytes.
        let kind = FleetKind::ALL[usize::from(key) % FleetKind::ALL.len()];
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
    let author = fixture.authors[usize::from(author) % 3];
    // A genuine entry's key, or one of the fuzzer's own naming.
    let key = fixture
        .keys
        .get(usize::from(key))
        .cloned()
        .unwrap_or_else(|| fixture.fleet_key.entry_key(&[key]).to_vec());
    let value = if mode % 3 == 0 {
        rest.to_vec()
    } else {
        // Sealed under the real fleet key for its place, as a holder of the
        // key could.
        fixture
            .fleet_key
            .seal(&[&DOC, &key], rest)
            .expect("scripted random")
    };
    let mut entries = fixture.genuine.clone();
    entries.push(FleetEntry { author, key, value });
    let read = read_fleet(&fixture.identity, &fixture.fleet_key, &DOC, entries);
    assert!(
        same_view(&read.view, &fixture.view),
        "an entry nobody signed changed the account"
    );
});
