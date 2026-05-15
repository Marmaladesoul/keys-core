//! Integration tests for [`Engine::project_to_vault`] (task 2.4).
//!
//! Each test builds an in-memory `Kdbx`, ingests it via task 2.3, then
//! projects back via task 2.4 and asserts the reconstructed model
//! matches the originating shape. The bigger gold-standard property
//! test (`kdbx → ingest → project → kdbx == original`) lands in task
//! 2.7.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{
    Attachment, Binary, CustomFieldValue, HistoryPolicy, NewEntry, NewGroup,
};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use secrecy::SecretString;

#[derive(Debug)]
struct FixedKey([u8; 32]);

impl KeyProvider for FixedKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.0))
    }
}

#[derive(Debug, Clone)]
struct FixedProtector([u8; 32]);

impl FieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Ok(SessionKey::from_bytes(self.0))
    }
}

const SESSION_KEY_BYTES: [u8; 32] = [0x9c; 32];
const DB_KEY_BYTES: [u8; 32] = [0x42; 32];

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn fresh_kdbx(protector: Arc<dyn FieldProtector>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector)).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector()).expect("open engine")
}

/// Round-trip `kdbx → ingest → project` and return the projected
/// vault. Shared by every test below.
fn round_trip(kdbx: &Kdbx<Unlocked>) -> keepass_core::model::Vault {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(kdbx).expect("ingest");
    let projected = engine.project_to_vault().expect("project");
    engine.close().expect("close");
    projected
}

#[test]
fn project_empty_vault() {
    let kdbx = fresh_kdbx(protector());
    let projected = round_trip(&kdbx);
    assert_eq!(projected.root.id, kdbx.vault().root.id);
    assert!(projected.root.groups.is_empty());
    assert!(projected.root.entries.is_empty());
    assert!(projected.binaries.is_empty());
}

#[test]
fn project_simple_vault() {
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let group_id = kdbx
        .add_group(root, NewGroup::new("Logins"))
        .expect("add group");
    let entry_id = kdbx
        .add_entry(
            group_id,
            NewEntry::new("acme")
                .username("alice")
                .url("https://login.example.com/path")
                .notes("note")
                .password(SecretString::from("Tr0ub4dor&3")),
        )
        .expect("add entry");

    let projected = round_trip(&kdbx);

    // Tree shape: root → Logins → acme.
    assert_eq!(projected.root.groups.len(), 1);
    let logins = &projected.root.groups[0];
    assert_eq!(logins.id, group_id);
    assert_eq!(logins.name, "Logins");
    assert_eq!(logins.entries.len(), 1);
    let entry = &logins.entries[0];
    assert_eq!(entry.id, entry_id);
    assert_eq!(entry.title, "acme");
    assert_eq!(entry.username, "alice");
    assert_eq!(entry.url, "https://login.example.com/path");
    assert_eq!(entry.notes, "note");
    assert_eq!(
        entry.password, "Tr0ub4dor&3",
        "plaintext password recovered"
    );
}

#[test]
fn project_with_history() {
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let entry_id = kdbx
        .add_entry(root, NewEntry::new("v0").password(SecretString::from("p0")))
        .expect("add");
    for title in ["v1", "v2", "v3"] {
        kdbx.edit_entry(entry_id, HistoryPolicy::Snapshot, |e| {
            e.set_title(title);
        })
        .expect("edit");
    }

    let projected = round_trip(&kdbx);
    let entry = projected
        .root
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .expect("entry present");
    assert_eq!(entry.title, "v3");
    assert_eq!(entry.history.len(), 3, "three prior snapshots");
    // History is oldest-first; the snapshots are the *pre-edit* states,
    // so the titles are v0, v1, v2 (the title at the time the edit
    // started, not the edit's new title).
    let titles: Vec<_> = entry.history.iter().map(|e| e.title.as_str()).collect();
    assert_eq!(titles, vec!["v0", "v1", "v2"]);
}

#[test]
fn project_with_attachments() {
    let mut kdbx = fresh_kdbx(protector());

    let shared = Binary::new(b"shared bytes".to_vec(), false);
    let other = Binary::new(b"different bytes".to_vec(), false);
    {
        let mut vault = kdbx.vault().clone();
        vault.binaries.push(shared.clone());
        vault.binaries.push(other.clone());
        kdbx.replace_vault(vault);
    }

    let root = kdbx.vault().root.id;
    let entry_a = kdbx.add_entry(root, NewEntry::new("a")).expect("add a");
    let entry_b = kdbx.add_entry(root, NewEntry::new("b")).expect("add b");
    {
        let mut vault = kdbx.vault().clone();
        for entry in &mut vault.root.entries {
            if entry.id == entry_a {
                entry.attachments.push(Attachment::new("shared.txt", 0));
                entry.attachments.push(Attachment::new("solo.txt", 1));
            } else if entry.id == entry_b {
                entry.attachments.push(Attachment::new("shared.txt", 0));
            }
        }
        kdbx.replace_vault(vault);
    }

    let projected = round_trip(&kdbx);

    // Resolve attachments via the projected binary pool.
    let resolve = |entry: &keepass_core::model::Entry, name: &str| -> Vec<u8> {
        let att = entry
            .attachments
            .iter()
            .find(|a| a.name == name)
            .expect("attachment present");
        projected.binaries[att.ref_id as usize].data.clone()
    };

    let pa = projected
        .root
        .entries
        .iter()
        .find(|e| e.id == entry_a)
        .expect("a");
    let pb = projected
        .root
        .entries
        .iter()
        .find(|e| e.id == entry_b)
        .expect("b");

    assert_eq!(resolve(pa, "shared.txt"), b"shared bytes");
    assert_eq!(resolve(pa, "solo.txt"), b"different bytes");
    assert_eq!(resolve(pb, "shared.txt"), b"shared bytes");
}

#[test]
fn project_with_tags() {
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let entry_id = kdbx
        .add_entry(
            root,
            NewEntry::new("tagged")
                .password(SecretString::from("pw"))
                .tags(vec!["banking".into(), "personal".into(), "email".into()]),
        )
        .expect("add");

    let projected = round_trip(&kdbx);
    let entry = projected
        .root
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .expect("entry");
    // Projection sorts tags alphabetically — see `load_tags` in
    // projection.rs for the rationale.
    assert_eq!(entry.tags, vec!["banking", "email", "personal"]);
}

#[test]
fn project_with_custom_fields_protected() {
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let entry_id = kdbx
        .add_entry(
            root,
            NewEntry::new("api").password(SecretString::from("pw")),
        )
        .expect("add");
    kdbx.edit_entry(entry_id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("secret-token")),
        );
    })
    .expect("edit");

    let projected = round_trip(&kdbx);
    let entry = projected
        .root
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .expect("entry");
    let token = entry
        .custom_fields
        .iter()
        .find(|f| f.key == "Token")
        .expect("token custom field");
    assert!(token.protected, "custom field stays protected");
    assert_eq!(token.value, "secret-token", "plaintext recovered");
}

#[test]
fn project_with_url_host_round_trip() {
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let entry_id = kdbx
        .add_entry(
            root,
            NewEntry::new("u").url("https://login.example.com/path"),
        )
        .expect("add");

    let projected = round_trip(&kdbx);
    let entry = projected
        .root
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .expect("entry");
    assert_eq!(entry.url, "https://login.example.com/path");
    // `url_host` is engine-internal: never surfaces on the projected
    // model. (No assertion needed — the type has no such field — but
    // documenting the invariant in the test name.)
}

#[test]
fn project_marks_recycle_bin() {
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let bin_id = kdbx
        .add_group(root, NewGroup::new("Recycle Bin"))
        .expect("add bin");
    kdbx.set_recycle_bin(true, Some(bin_id));

    let projected = round_trip(&kdbx);
    assert_eq!(projected.meta.recycle_bin_uuid, Some(bin_id));
    assert!(projected.meta.recycle_bin_enabled);
}

#[test]
fn project_preserves_group_hierarchy() {
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let depth1 = kdbx.add_group(root, NewGroup::new("d1")).expect("d1");
    let depth2 = kdbx.add_group(depth1, NewGroup::new("d2")).expect("d2");
    let _depth3 = kdbx.add_group(depth2, NewGroup::new("d3")).expect("d3");

    let projected = round_trip(&kdbx);
    assert_eq!(projected.root.groups.len(), 1);
    let d1 = &projected.root.groups[0];
    assert_eq!(d1.name, "d1");
    assert_eq!(d1.groups.len(), 1);
    let d2 = &d1.groups[0];
    assert_eq!(d2.name, "d2");
    assert_eq!(d2.groups.len(), 1);
    let d3 = &d2.groups[0];
    assert_eq!(d3.name, "d3");
    assert!(d3.groups.is_empty());
}
