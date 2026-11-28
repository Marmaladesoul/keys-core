//! `account-heads`: a vault document's signed head records, read through the
//! seam over real document sync.
//!
//! Every device is a node of its own on the loopback interface. Alice and
//! Bob are two devices of one account, each enrolled with its node's real
//! endpoint and author ids. Alice publishes her copy of a vault: the copy
//! under the copy key and her signed head under the head key, both with her
//! author. Bob joins the document with nothing downloaded by default and
//! reads it as a client must ([`Device::read`] is that contract in code):
//! for each entry, ask the roster whether to fetch it as a head; fetch only
//! those; check each fetched head; and only for a head that checks out,
//! fetch the copy it names, by its hash, with its size as the cap.
//!
//! Each case adds one thing that must not work. A thief who has Alice's
//! document store holds her author secret, so the thief's writes are played
//! by Alice's own node writing what Alice never signed.
//!
//! Output is one `who: what` line per event, for scenarios to grep. Every
//! fetch Bob makes is a `bob: fetch` line, so a scenario can show something
//! was never fetched.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use keys_ffi::keys_iroh_sync::{DownloadPolicy, EntryInfo};
use keys_ffi::{
    AccountRoster, DeviceSyncKeys, PairingDeviceKeys, VaultHeadCheck, VaultHeadFetch,
    generate_pairing_account, vault_copy_entry_key, vault_head_entry_key,
};

use crate::account_net::{Device, Names, byte_len, sequence, unhex};
use crate::pairing::{hex, kebab};

/// The most Bob will fetch for a copy.
const COPY_CAP_BYTES: u64 = 1 << 20;
/// What else happens in the document.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HeadsCase {
    /// Nothing: Bob reads Alice's copy.
    Honest,
    /// Mallory, a device of another account holding the document's write
    /// ticket, publishes a head and copy of her own.
    Stranger,
    /// A thief with Alice's author writes a head under it that a key of the
    /// thief's own signed; then Alice notices and writes hers again.
    Forged,
    /// Alice's genuine head for another document is written into this one.
    Moved,
    /// After Bob has accepted Alice's newer head, a thief with her author
    /// puts her older head back.
    Replayed,
    /// Alice's head names a copy larger than Bob will fetch.
    Oversize,
    /// Alice's newer head names a copy no entry offers yet, so Bob's fetch
    /// of it fails; then she writes the copy. Bob must read her entries
    /// after the failed one, and read the same head again once the copy is
    /// there.
    Unserved,
}

impl Device {
    /// Writes `copy` under the copy key and a head for it, signed with
    /// `sequence` and placed for `signed_for`, under the head key. Returns
    /// the head's bytes and its content hash.
    async fn publish(
        &self,
        doc: &str,
        signed_for: &str,
        sequence: u64,
        copy: &[u8],
    ) -> Result<(Vec<u8>, String)> {
        self.publish_claiming(doc, signed_for, sequence, copy, byte_len(copy))
            .await
    }

    /// [`Self::publish`] with a head that says the copy is `claimed_size`
    /// bytes, whatever its real size.
    async fn publish_claiming(
        &self,
        doc: &str,
        signed_for: &str,
        sequence: u64,
        copy: &[u8],
        claimed_size: u64,
    ) -> Result<(Vec<u8>, String)> {
        let copy_hash = self
            .node
            .set_entry(doc.to_owned(), vault_copy_entry_key(), copy.to_vec())
            .await?;
        let head = self.sync_keys.sign_vault_head(
            unhex(signed_for)?,
            sequence,
            unhex(&copy_hash)?,
            claimed_size,
        )?;
        let head_hash = self.write_head(doc, &head).await?;
        Ok((head, head_hash))
    }

    /// Writes `head` under this node's author at the head key, whoever
    /// signed it.
    async fn write_head(&self, doc: &str, head: &[u8]) -> Result<String> {
        Ok(self
            .node
            .set_entry(doc.to_owned(), vault_head_entry_key(), head.to_vec())
            .await?)
    }

    /// Waits until this node holds `author`'s head entry with `hash`.
    async fn wait_for_head(&self, doc: &str, author: &[u8], hash: &str) -> Result<()> {
        self.wait_for_entry(doc, author, &vault_head_entry_key(), hash)
            .await
    }

    /// The reader's contract: every other author's entry in `doc` checked
    /// against `roster`, nothing fetched until it checks out. `accepted`
    /// holds the last sequence accepted from each device here, and is
    /// updated. One entry's failure is that entry's: it is reported and the
    /// rest are still read, so one author's entries can't hide another's.
    async fn read(
        &self,
        doc: &str,
        roster: &AccountRoster,
        accepted: &mut HashMap<Vec<u8>, u64>,
        names: &Names,
    ) -> Result<()> {
        let mut entries = self.node.list_entries(doc.to_owned()).await?;
        entries.sort_by(|a, b| (&a.author, &a.key).cmp(&(&b.author, &b.key)));
        for entry in entries {
            let author = unhex(&entry.author)?;
            if author == self.author {
                continue;
            }
            let who = names.author(&author);
            if let Err(error) = self
                .read_entry(doc, roster, accepted, names, &entry, &author)
                .await
            {
                println!("{}: failed author={who} error={error:#}", self.name);
            }
        }
        Ok(())
    }

    /// [`Self::read`] for one entry, written by `author`.
    async fn read_entry(
        &self,
        doc: &str,
        roster: &AccountRoster,
        accepted: &mut HashMap<Vec<u8>, u64>,
        names: &Names,
        entry: &EntryInfo,
        author: &[u8],
    ) -> Result<()> {
        let who = names.author(author);
        let device =
            match roster.head_to_fetch(author.to_vec(), entry.key.clone(), entry.size_bytes)? {
                VaultHeadFetch::Fetch { device_id } => device_id,
                VaultHeadFetch::Ignore { reason } => {
                    println!(
                        "{}: ignored author={who} entry={} reason={}",
                        self.name,
                        key_name(entry),
                        kebab(&format!("{reason:?}"))
                    );
                    return Ok(());
                }
            };
        println!("{}: fetch head author={who}", self.name);
        let head = self
            .node
            .fetch_checked_blob(doc.to_owned(), entry.hash_hex.clone(), entry.size_bytes)
            .await?;
        let check = roster.accept_vault_head(
            unhex(doc)?,
            author.to_vec(),
            head,
            accepted.get(&device).copied(),
            COPY_CAP_BYTES,
        )?;
        match check {
            VaultHeadCheck::Accepted {
                device_id,
                sequence,
                content_hash,
                size_bytes,
            } => {
                let owner = names.device(&device_id);
                println!("{}: accepted head author={who} owner={owner}", self.name);
                println!("{}: fetch copy owner={owner}", self.name);
                let copy = self
                    .node
                    .fetch_checked_blob(doc.to_owned(), hex(&content_hash), size_bytes)
                    .await?;
                // Only now is the head done with: a copy that didn't
                // arrive leaves it to be read again.
                accepted.insert(device_id, sequence);
                println!(
                    "{}: copy owner={owner} content={}",
                    self.name,
                    String::from_utf8_lossy(&copy)
                );
            }
            VaultHeadCheck::Refused { reason } => println!(
                "{}: refused head author={who} reason={}",
                self.name,
                kebab(&format!("{reason:?}"))
            ),
        }
        Ok(())
    }

    /// Whether the head under this device's own author in `doc` is one it
    /// signed: what a device checks on seeing its own author's entry change.
    async fn own_head_is_mine(&self, doc: &str, roster: &AccountRoster) -> Result<bool> {
        let own = hex(&self.author);
        let entries = self.node.list_entries(doc.to_owned()).await?;
        let head = entries
            .iter()
            .find(|e| e.author == own && e.key == vault_head_entry_key())
            .context("no head under this device's author")?;
        let bytes = self
            .node
            .fetch_checked_blob(doc.to_owned(), head.hash_hex.clone(), head.size_bytes)
            .await?;
        let check = roster.accept_vault_head(
            unhex(doc)?,
            self.author.clone(),
            bytes,
            None,
            COPY_CAP_BYTES,
        )?;
        Ok(matches!(
            check,
            VaultHeadCheck::Accepted { device_id, .. } if device_id == self.keys.public_keys().signing
        ))
    }
}

fn key_name(entry: &EntryInfo) -> String {
    String::from_utf8_lossy(&entry.key).into_owned()
}

/// Everything a case starts from: the three devices, the account's roster,
/// and Alice's first head, already synced to Bob.
struct World {
    alice: Device,
    bob: Device,
    mallory: Device,
    roster: Arc<AccountRoster>,
    names: Names,
    doc: String,
    ticket: String,
    first: u64,
    old_head: Vec<u8>,
    head_hash: String,
}

/// What happens in the document for `case`, after Alice's first head.
async fn play(case: HeadsCase, world: &World, accepted: &mut HashMap<Vec<u8>, u64>) -> Result<()> {
    let World {
        alice,
        bob,
        mallory,
        roster,
        names,
        doc,
        ticket,
        first,
        old_head,
        head_hash,
    } = world;
    let first = *first;
    match case {
        HeadsCase::Honest => {
            let mine = alice.own_head_is_mine(doc, roster).await?;
            println!(
                "alice: own head is hers={}",
                if mine { "yes" } else { "no" }
            );
        }
        HeadsCase::Stranger => {
            mallory
                .node
                .join_doc(ticket.clone(), DownloadPolicy::Everything)
                .await?;
            let (_, hash) = mallory
                .publish(doc, doc, sequence(None)?, b"mallory")
                .await?;
            bob.wait_for_head(doc, &mallory.author, &hash).await?;
        }
        HeadsCase::Forged => {
            // The thief's head names a copy of the thief's, signed by a key
            // that is no device of this account's.
            let thief =
                DeviceSyncKeys::from_stored(PairingDeviceKeys::generate()?.sync_stored_form())?;
            let junk_copy = b"thief";
            let junk = alice
                .node
                .set_entry(doc.clone(), b"junk".to_vec(), junk_copy.to_vec())
                .await?;
            let forged = thief.sign_vault_head(
                unhex(doc)?,
                sequence(Some(first))?,
                unhex(&junk)?,
                byte_len(junk_copy),
            )?;
            let hash = alice.write_head(doc, &forged).await?;
            bob.wait_for_head(doc, &alice.author, &hash).await?;
            bob.read(doc, roster, accepted, names).await?;
            // Alice checks the head under her author, finds one she didn't
            // sign, and writes her own again, above her last sequence.
            let mine = alice.own_head_is_mine(doc, roster).await?;
            println!(
                "alice: own head is hers={}",
                if mine { "yes" } else { "no" }
            );
            let (_, hash) = alice
                .publish(doc, doc, sequence(Some(first))?, b"alice-2")
                .await?;
            bob.wait_for_head(doc, &alice.author, &hash).await?;
        }
        HeadsCase::Moved => {
            let other = alice.node.create_doc().await?;
            let (_, hash) = alice
                .publish(doc, &other, sequence(Some(first))?, b"alice-other")
                .await?;
            bob.wait_for_head(doc, &alice.author, &hash).await?;
        }
        HeadsCase::Replayed => {
            bob.read(doc, roster, accepted, names).await?;
            let (_, hash) = alice
                .publish(doc, doc, sequence(Some(first))?, b"alice-2")
                .await?;
            bob.wait_for_head(doc, &alice.author, &hash).await?;
            bob.read(doc, roster, accepted, names).await?;
            // The thief puts the older head back under Alice's author.
            alice.write_head(doc, old_head).await?;
            bob.wait_for_head(doc, &alice.author, head_hash).await?;
        }
        HeadsCase::Oversize => {
            let (_, hash) = alice
                .publish_claiming(
                    doc,
                    doc,
                    sequence(Some(first))?,
                    b"alice-2",
                    COPY_CAP_BYTES + 1,
                )
                .await?;
            bob.wait_for_head(doc, &alice.author, &hash).await?;
        }
        HeadsCase::Unserved => unserved(world, accepted).await?,
    }
    Ok(())
}

/// The `Unserved` case: a head whose copy no entry offers yet, then the copy.
async fn unserved(world: &World, accepted: &mut HashMap<Vec<u8>, u64>) -> Result<()> {
    let World {
        alice,
        bob,
        roster,
        names,
        doc,
        first,
        ..
    } = world;
    let first = *first;
    // The copy's bytes go into another document only, so Alice's
    // store holds them but nothing in this one names them.
    let copy = b"alice-2";
    let elsewhere = alice.node.create_doc().await?;
    let copy_hash = alice
        .node
        .set_entry(elsewhere, b"elsewhere".to_vec(), copy.to_vec())
        .await?;
    let head = alice.sync_keys.sign_vault_head(
        unhex(doc)?,
        sequence(Some(first))?,
        unhex(&copy_hash)?,
        byte_len(copy),
    )?;
    let hash = alice.write_head(doc, &head).await?;
    // An entry of Alice's that Bob reads after her head.
    let after = alice
        .node
        .set_entry(doc.clone(), AFTER_HEAD_KEY.to_vec(), b"later".to_vec())
        .await?;
    bob.wait_for_head(doc, &alice.author, &hash).await?;
    bob.wait_for_entry(doc, &alice.author, AFTER_HEAD_KEY, &after)
        .await?;
    bob.read(doc, roster, accepted, names).await?;
    // Now the copy is offered.
    let offered = alice
        .node
        .set_entry(doc.clone(), vault_copy_entry_key(), copy.to_vec())
        .await?;
    bob.wait_for_entry(doc, &alice.author, &vault_copy_entry_key(), &offered)
        .await?;
    Ok(())
}

/// An entry key that sorts after the head key, for an entry the reader
/// meets after a head.
const AFTER_HEAD_KEY: &[u8] = b"zz-after-head";
const _: () = assert!(AFTER_HEAD_KEY[0] > b"keys/v1/vault/head"[0]);

/// `account-heads`: run one case end to end.
pub async fn run(case: HeadsCase) -> Result<()> {
    let account = generate_pairing_account()?.keys;
    let alice = Device::start("alice").await?;
    let bob = Device::start("bob").await?;
    let mallory = Device::start("mallory").await?;
    let roster = AccountRoster::open(
        account.public_keys().identity,
        vec![alice.enrol(&account)?, bob.enrol(&account)?],
    )?;
    let names = Names::of(&[&alice, &bob, &mallory]);
    let mut accepted = HashMap::new();

    let doc = alice.node.create_doc().await?;
    let first = sequence(None)?;
    let (old_head, head_hash) = alice.publish(&doc, &doc, first, b"alice-1").await?;
    let ticket = alice.node.share_doc(doc.clone(), true).await?;
    bob.node
        .join_doc(
            ticket.clone(),
            DownloadPolicy::NothingExcept {
                key_prefixes: Vec::new(),
            },
        )
        .await?;
    bob.wait_for_head(&doc, &alice.author, &head_hash).await?;

    let world = World {
        alice,
        bob,
        mallory,
        roster,
        names,
        doc,
        ticket,
        first,
        old_head,
        head_hash,
    };
    play(case, &world, &mut accepted).await?;
    world
        .bob
        .read(&world.doc, &world.roster, &mut accepted, &world.names)
        .await?;

    for device in [world.alice, world.bob, world.mallory] {
        device.node.shutdown().await?;
    }
    println!("result: done");
    Ok(())
}
