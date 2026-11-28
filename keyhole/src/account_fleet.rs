//! `account-fleet`: the account's fleet document, sealed under the fleet
//! key, read through the seam over real document sync.
//!
//! Every device is a node of its own on the loopback interface. Alice
//! creates the account: its keys, the fleet key and the fleet document, and
//! writes her own enrolment, what she says about herself, her name, a vault's
//! epoch and look, and a setting. Bob is enrolled by the account (what Add
//! Device will do over pairing; here he is handed the account and fleet keys
//! directly) and writes his own enrolment, name, what he says about himself,
//! and what he holds of the vault. Bob joins with nothing downloaded by
//! default and fetches every entry small enough to be a record, from any
//! author: the roster that says which authors count is itself in the
//! document. Each reader passes back the entries it kept from its last read
//! (`Member::read` is that contract in code).
//!
//! Each case adds one thing that must not work. A thief who has Alice's
//! document store holds her author secret, and is played by Alice's own node
//! writing what Alice never signed.
//!
//! Output is one `who: what` line per event, for scenarios to grep.

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use anyhow::{Context, Result};
use keys_ffi::keys_iroh_sync::DownloadPolicy;
use keys_ffi::{
    DeviceSyncKeys, FleetEntryRecord, FleetKey, FleetReadResult, FleetRecordInput,
    PairingAccountKeys, PairingDeviceKeys, fleet_entry_max_bytes, fleet_entry_to_fetch,
    generate_pairing_account, read_fleet,
};

use crate::account_net::{Device, Names, sequence, unhex};
use crate::pairing::kebab;

/// The vault in the index.
const VAULT_ID: [u8; 16] = [0x7a; 16];
const VAULT_NAME: &str = "Family";
const VAULT_ICON: &str = "house";
const VAULT_COLOUR: u32 = 0x002a_7ab0;
const SETTING_NAME: &str = "cellular-cap";

/// What else happens in the document.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FleetCase {
    /// Nothing: each reads the other.
    Honest,
    /// Mallory, holding the document's write ticket but not the fleet key,
    /// writes records of her own account's.
    Stranger,
    /// A thief with Alice's store and the fleet key, but not her device key,
    /// writes a name for her under her author with a key of its own, over
    /// her own name record, after Bob has read it.
    Thief,
    /// The account removes Bob; Bob writes his enrolment back and goes on
    /// writing.
    Removed,
    /// The vault moves to epoch 2; once Bob has read it, a thief with
    /// Alice's author puts her epoch-1 record back.
    Replayed,
    /// Bob renames Alice; both readers settle on the same name.
    Renamed,
}

/// The fleet document as one account sees it.
struct Fleet {
    identity: Vec<u8>,
    key: Arc<FleetKey>,
    doc: String,
}

/// A device in the fleet: the last sequence it used there, and what it kept
/// from its last read.
struct Member {
    device: Device,
    last_sequence: Cell<Option<u64>>,
    kept: RefCell<Vec<FleetEntryRecord>>,
}

/// An entry as written, to wait for on another node.
#[derive(Clone)]
struct Written {
    author: Vec<u8>,
    key: Vec<u8>,
    hash: String,
}

impl Member {
    async fn start(name: &'static str) -> Result<Self> {
        Ok(Self {
            device: Device::start(name).await?,
            last_sequence: Cell::new(None),
            kept: RefCell::new(Vec::new()),
        })
    }

    fn name(&self) -> &'static str {
        self.device.name
    }

    /// Seals `record` with `keys` for `fleet` at this device's next
    /// sequence and writes it under this device's author.
    async fn write_signed_by(
        &self,
        fleet: &Fleet,
        keys: &DeviceSyncKeys,
        record: FleetRecordInput,
    ) -> Result<Written> {
        let next = sequence(self.last_sequence.get())?;
        self.last_sequence.set(Some(next));
        let sealed = keys.seal_fleet_record(
            fleet.key.clone(),
            fleet.identity.clone(),
            unhex(&fleet.doc)?,
            next,
            record,
        )?;
        self.write_raw(fleet, sealed.key, sealed.value).await
    }

    async fn write(&self, fleet: &Fleet, record: FleetRecordInput) -> Result<Written> {
        self.write_signed_by(fleet, &self.device.sync_keys, record)
            .await
    }

    async fn write_raw(&self, fleet: &Fleet, key: Vec<u8>, value: Vec<u8>) -> Result<Written> {
        let hash = self
            .device
            .node
            .set_entry(fleet.doc.clone(), key.clone(), value)
            .await?;
        Ok(Written {
            author: self.device.author.clone(),
            key,
            hash,
        })
    }

    async fn wait_for(&self, fleet: &Fleet, written: &[Written]) -> Result<()> {
        for w in written {
            self.device
                .wait_for_entry(&fleet.doc, &w.author, &w.key, &w.hash)
                .await?;
        }
        Ok(())
    }

    /// The reader's contract: fetch every entry small enough to be a record,
    /// from any author, read them with what was kept last time, and keep
    /// what the read says to keep. One entry's failed fetch is that entry's.
    async fn read(&self, fleet: &Fleet, names: &Names, epochs: &Epochs) -> Result<FleetReadResult> {
        let name = self.name();
        let mut entries = self.device.node.list_entries(fleet.doc.clone()).await?;
        entries.sort_by(|a, b| (&a.author, &a.key).cmp(&(&b.author, &b.key)));
        let mut found = Vec::new();
        for entry in entries {
            let author = unhex(&entry.author)?;
            if !fleet_entry_to_fetch(entry.size_bytes) {
                println!(
                    "{name}: ignored author={} reason=too-large",
                    names.author(&author)
                );
                continue;
            }
            match self
                .device
                .node
                .fetch_checked_blob(fleet.doc.clone(), entry.hash_hex, fleet_entry_max_bytes())
                .await
            {
                Ok(value) => found.push(FleetEntryRecord {
                    author,
                    key: entry.key,
                    value,
                }),
                Err(error) => println!(
                    "{name}: failed author={} error={error:#}",
                    names.author(&author)
                ),
            }
        }
        let mut input = self.kept.borrow().clone();
        input.extend(found);
        let read = read_fleet(
            fleet.identity.clone(),
            fleet.key.clone(),
            unhex(&fleet.doc)?,
            input,
        )?;
        self.kept.replace(read.kept.clone());
        print_view(name, &read, names, epochs);
        Ok(read)
    }
}

/// The vault documents, to name them in output.
struct Epochs {
    first: Vec<u8>,
    second: Vec<u8>,
}

impl Epochs {
    fn name(&self, doc: &[u8]) -> &'static str {
        if doc == self.first {
            "first"
        } else if doc == self.second {
            "second"
        } else {
            "unknown"
        }
    }
}

fn print_view(who: &str, read: &FleetReadResult, names: &Names, epochs: &Epochs) {
    for device in &read.devices {
        let id = &device.enrolment.device_id;
        println!(
            "{who}: device {} name={} platform={}",
            names.device(id),
            device.name.as_deref().unwrap_or("-"),
            device.info.as_ref().map_or("-", |i| i.platform.as_str()),
        );
    }
    for removed in &read.removed {
        println!("{who}: removed {}", names.device(removed));
    }
    for vault in &read.vaults {
        let look = vault.look.as_ref();
        println!(
            "{who}: vault epoch={} doc={} name={} icon={} colour={}",
            vault.epoch,
            epochs.name(&vault.doc_id),
            look.map_or("-", |l| l.name.as_str()),
            look.map_or("-", |l| l.icon.as_str()),
            look.map_or_else(|| "-".to_owned(), |l| format!("{:06x}", l.colour_rgb)),
        );
        for holding in &vault.holdings {
            println!(
                "{who}: holding device={} epoch={} secrets={}",
                names.device(&holding.device_id),
                holding.epoch,
                if holding.has_secrets { "yes" } else { "no" },
            );
        }
    }
    for setting in &read.settings {
        println!(
            "{who}: setting {}={}",
            setting.name,
            String::from_utf8_lossy(&setting.value)
        );
    }
    for refusal in &read.refused {
        println!(
            "{who}: refused author={} reason={}",
            names.author(&refusal.author),
            kebab(&format!("{:?}", refusal.reason))
        );
    }
    let mut roster: Vec<&str> = read
        .roster
        .device_ids()
        .iter()
        .map(|id| names.device(id))
        .collect();
    roster.sort_unstable();
    println!("{who}: roster {}", roster.join(","));
}

fn name_record(device: &Device, name: &str) -> FleetRecordInput {
    FleetRecordInput::DeviceName {
        device_id: device.keys.public_keys().signing,
        name: name.to_owned(),
    }
}

fn info_record(platform: &str) -> FleetRecordInput {
    FleetRecordInput::DeviceInfo {
        platform: platform.to_owned(),
        paired_at: 1,
        last_seen: 1,
    }
}

fn epoch_record(account: &PairingAccountKeys, doc: &[u8], epoch: u64) -> Result<FleetRecordInput> {
    Ok(FleetRecordInput::VaultEpoch {
        vault_epoch: account.sign_vault_epoch(VAULT_ID.to_vec(), doc.to_vec(), epoch)?,
    })
}

/// Everything a case starts from: the account, its fleet, and both devices'
/// first records, synced across.
struct World {
    account: Arc<PairingAccountKeys>,
    fleet: Fleet,
    alice: Member,
    bob: Member,
    mallory: Member,
    ticket: String,
    names: Names,
    epochs: Epochs,
    first_epoch: Written,
    first_epoch_value: Vec<u8>,
}

/// What happens in the document for `case`, after the first records.
async fn play(case: FleetCase, world: &World) -> Result<()> {
    let World {
        account,
        fleet,
        alice,
        bob,
        mallory,
        ticket,
        names,
        epochs,
        first_epoch,
        first_epoch_value,
    } = world;
    match case {
        FleetCase::Honest => {
            alice.read(fleet, names, epochs).await?;
        }
        FleetCase::Stranger => {
            // Mallory's own account and fleet key, in Alice's document.
            let other = generate_pairing_account()?.keys;
            let theirs = Fleet {
                identity: other.public_keys().identity,
                key: FleetKey::generate()?,
                doc: fleet.doc.clone(),
            };
            mallory
                .device
                .node
                .join_doc(ticket.clone(), DownloadPolicy::Everything)
                .await?;
            let written = [
                mallory
                    .write(
                        &theirs,
                        FleetRecordInput::Enrolment {
                            enrolment: mallory.device.enrol(&other)?,
                        },
                    )
                    .await?,
                mallory
                    .write(&theirs, name_record(&mallory.device, "Mallory"))
                    .await?,
            ];
            bob.wait_for(fleet, &written).await?;
        }
        FleetCase::Thief => {
            // Bob has read Alice's name before the thief writes over it.
            bob.read(fleet, names, epochs).await?;
            let thief =
                DeviceSyncKeys::from_stored(PairingDeviceKeys::generate()?.sync_stored_form())?;
            let written = alice
                .write_signed_by(fleet, &thief, name_record(&alice.device, "Thief"))
                .await?;
            bob.wait_for(fleet, &[written]).await?;
        }
        FleetCase::Removed => {
            let tombstone = account.sign_device_tombstone(bob.device.keys.public_keys().signing)?;
            let removal = alice
                .write(fleet, FleetRecordInput::Tombstone { tombstone })
                .await?;
            bob.wait_for(fleet, &[removal]).await?;
            // Removed, Bob writes himself back and goes on writing.
            let written = [
                bob.write(
                    fleet,
                    FleetRecordInput::Enrolment {
                        enrolment: bob.device.enrol(account)?,
                    },
                )
                .await?,
                bob.write(fleet, name_record(&bob.device, "Still Bob"))
                    .await?,
                bob.write(fleet, name_record(&alice.device, "Bob was here"))
                    .await?,
            ];
            alice.wait_for(fleet, &written).await?;
            alice.read(fleet, names, epochs).await?;
        }
        FleetCase::Replayed => {
            let moved = alice
                .write(fleet, epoch_record(account, &epochs.second, 2)?)
                .await?;
            bob.wait_for(fleet, &[moved]).await?;
            bob.read(fleet, names, epochs).await?;
            // The thief puts Alice's epoch-1 record back under her author.
            let replayed = alice
                .write_raw(fleet, first_epoch.key.clone(), first_epoch_value.clone())
                .await?;
            bob.wait_for(fleet, &[replayed]).await?;
        }
        FleetCase::Renamed => {
            let renamed = bob
                .write(fleet, name_record(&alice.device, "Kitchen Mac"))
                .await?;
            alice.wait_for(fleet, &[renamed]).await?;
            alice.read(fleet, names, epochs).await?;
        }
    }
    Ok(())
}

/// Alice's first records, with her epoch-1 record and its value kept apart
/// for the replay.
struct FromAlice {
    written: Vec<Written>,
    first_epoch: Written,
    first_epoch_value: Vec<u8>,
}

/// Account creation on Alice: this device's roster entry first, then what
/// she says about herself, her name, the vault's first epoch and look, and a
/// setting.
async fn alice_creates(
    account: &Arc<PairingAccountKeys>,
    alice: &Member,
    fleet: &Fleet,
    epochs: &Epochs,
) -> Result<FromAlice> {
    let mut from_alice = vec![
        alice
            .write(
                fleet,
                FleetRecordInput::Enrolment {
                    enrolment: alice.device.enrol(account)?,
                },
            )
            .await?,
        alice.write(fleet, info_record("macos")).await?,
        alice
            .write(fleet, name_record(&alice.device, "Alice's Mac"))
            .await?,
    ];
    let first_epoch_input = epoch_record(account, &epochs.first, 1)?;
    let first_epoch = alice.write(fleet, first_epoch_input).await?;
    let first_epoch_value = alice
        .device
        .node
        .fetch_checked_blob(
            fleet.doc.clone(),
            first_epoch.hash.clone(),
            fleet_entry_max_bytes(),
        )
        .await
        .context("Alice reads back her own epoch record")?;
    from_alice.push(
        alice
            .write(
                fleet,
                FleetRecordInput::VaultLook {
                    vault_id: VAULT_ID.to_vec(),
                    name: VAULT_NAME.to_owned(),
                    icon: VAULT_ICON.to_owned(),
                    colour_rgb: VAULT_COLOUR,
                },
            )
            .await?,
    );
    from_alice.push(
        alice
            .write(
                fleet,
                FleetRecordInput::Setting {
                    name: SETTING_NAME.to_owned(),
                    value: b"on".to_vec(),
                },
            )
            .await?,
    );

    Ok(FromAlice {
        written: from_alice,
        first_epoch,
        first_epoch_value,
    })
}

/// `account-fleet`: run one case end to end.
pub async fn run(case: FleetCase) -> Result<()> {
    let account = generate_pairing_account()?.keys;
    let alice = Member::start("alice").await?;
    let bob = Member::start("bob").await?;
    let mallory = Member::start("mallory").await?;
    let names = Names::of(&[&alice.device, &bob.device, &mallory.device]);

    // Account creation: the fleet key and document, and this device's
    // roster entry.
    let fleet = Fleet {
        identity: account.public_keys().identity,
        key: FleetKey::generate()?,
        doc: alice.device.node.create_doc().await?,
    };
    let epochs = Epochs {
        first: unhex(&alice.device.node.create_doc().await?)?,
        second: unhex(&alice.device.node.create_doc().await?)?,
    };
    let FromAlice {
        written: mut from_alice,
        first_epoch,
        first_epoch_value,
    } = alice_creates(&account, &alice, &fleet, &epochs).await?;

    // Bob joins with nothing downloaded by default, enrolled by the account.
    let ticket = alice.device.node.share_doc(fleet.doc.clone(), true).await?;
    bob.device
        .node
        .join_doc(
            ticket.clone(),
            DownloadPolicy::NothingExcept {
                key_prefixes: Vec::new(),
            },
        )
        .await?;
    let from_bob = vec![
        bob.write(
            &fleet,
            FleetRecordInput::Enrolment {
                enrolment: bob.device.enrol(&account)?,
            },
        )
        .await?,
        bob.write(&fleet, info_record("android")).await?,
        bob.write(&fleet, name_record(&bob.device, "Bob's Phone"))
            .await?,
        bob.write(
            &fleet,
            FleetRecordInput::Holding {
                vault_id: VAULT_ID.to_vec(),
                epoch: 1,
                has_secrets: false,
                own_head: None,
                peer_heads: Vec::new(),
            },
        )
        .await?,
    ];
    from_alice.push(first_epoch.clone());
    bob.wait_for(&fleet, &from_alice).await?;
    alice.wait_for(&fleet, &from_bob).await?;

    let world = World {
        account,
        fleet,
        alice,
        bob,
        mallory,
        ticket,
        names,
        epochs,
        first_epoch,
        first_epoch_value,
    };
    play(case, &world).await?;
    let World {
        fleet,
        alice,
        bob,
        mallory,
        names,
        epochs,
        ..
    } = world;
    bob.read(&fleet, &names, &epochs).await?;
    if case == FleetCase::Replayed {
        // What a reader that lost its kept entries would see.
        bob.kept.replace(Vec::new());
        println!("bob: forgets what it kept");
        bob.read(&fleet, &names, &epochs).await?;
    }

    for member in [alice, bob, mallory] {
        member.device.node.shutdown().await?;
    }
    println!("result: done");
    Ok(())
}
