//! Integration tests for the Phase 4.2 / 4.3 change-event bus.

use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{Entry, EntryId, Group, GroupId};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    ChangeEvent, DataChangeObserver, DbKey, Engine, EntryUpdate, IconRef, KeyProvider,
    KeyProviderError, NewEntryFields, NewGroupFields, Predicate,
};
use secrecy::SecretString;
use uuid::Uuid;

// ── Fixtures ──────────────────────────────────────────────────────────

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

fn engine_with_empty_vault() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx(protector());
    let root_uuid = kdbx.vault().root.id.0;
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, root_uuid, dir)
}

fn new_entry(title: &str, password: &str) -> NewEntryFields {
    NewEntryFields {
        title: title.into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from(password),
        icon: IconRef::Builtin(0),
        custom_fields: Vec::new(),
        tags: Vec::new(),
    }
}

fn new_group(name: &str) -> NewGroupFields {
    NewGroupFields {
        name: name.into(),
        notes: String::new(),
        icon: IconRef::Builtin(0),
    }
}

#[derive(Default, Debug)]
struct CaptureObserver {
    events: Mutex<Vec<ChangeEvent>>,
}

impl CaptureObserver {
    fn snapshot(&self) -> Vec<ChangeEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl DataChangeObserver for CaptureObserver {
    fn on_event(&self, event: ChangeEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn install_observer(engine: &mut Engine) -> Arc<CaptureObserver> {
    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());
    observer
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn create_entry_emits_entries_added() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let observer = install_observer(&mut engine);
    let uuid = engine.create_entry(root, new_entry("a", "p")).expect("ce");
    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::EntriesAdded(v) => assert_eq!(v, &vec![uuid]),
        other => panic!("expected EntriesAdded, got {other:?}"),
    }
}

#[test]
fn update_entry_emits_entries_updated() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine.create_entry(root, new_entry("a", "p")).expect("ce");
    let observer = install_observer(&mut engine);
    let upd = EntryUpdate {
        title: Some("renamed".into()),
        ..EntryUpdate::default()
    };
    engine.update_entry(uuid, upd).expect("update");
    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::EntriesUpdated(v) => assert_eq!(v, &vec![uuid]),
        other => panic!("expected EntriesUpdated, got {other:?}"),
    }
}

#[test]
fn recycle_then_restore_emits_correct_events() {
    let (mut engine, root, _dir) = vault_with_recycle_bin();
    let uuid = engine.create_entry(root, new_entry("a", "p")).expect("ce");
    let observer = install_observer(&mut engine);
    engine.recycle_entry(uuid).expect("recycle");
    engine.restore_entry(uuid).expect("restore");
    let events = observer.snapshot();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], ChangeEvent::EntriesRecycled(ref v) if v == &vec![uuid]));
    assert!(matches!(events[1], ChangeEvent::EntriesRestored(ref v) if v == &vec![uuid]));
}

#[test]
fn delete_entry_emits_with_previous_group() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine.create_entry(root, new_entry("a", "p")).expect("ce");
    let observer = install_observer(&mut engine);
    engine.delete_entry(uuid).expect("delete");
    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::EntriesDeleted(v) => {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].uuid, uuid);
            assert_eq!(v[0].previous_group, root);
        }
        other => panic!("expected EntriesDeleted, got {other:?}"),
    }
}

#[test]
fn move_entry_emits_with_from_and_to() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let g = engine.create_group(root, new_group("dest")).expect("cg");
    let uuid = engine.create_entry(root, new_entry("a", "p")).expect("ce");
    let observer = install_observer(&mut engine);
    engine.move_entry(uuid, g).expect("move");
    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::EntriesMoved(v) => {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].uuid, uuid);
            assert_eq!(v[0].from_group, root);
            assert_eq!(v[0].to_group, g);
        }
        other => panic!("expected EntriesMoved, got {other:?}"),
    }
}

#[test]
fn set_protected_field_emits_protected_field_changed() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine.create_entry(root, new_entry("a", "p")).expect("ce");
    let observer = install_observer(&mut engine);
    engine
        .set_protected_field(uuid, "ApiKey", SecretString::from("sekrit"))
        .expect("set");
    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::ProtectedFieldChanged {
            entry_uuid,
            field_name,
        } => {
            assert_eq!(*entry_uuid, uuid);
            assert_eq!(field_name, "ApiKey");
        }
        other => panic!("expected ProtectedFieldChanged, got {other:?}"),
    }
}

#[test]
fn attach_file_emits_attachments_changed() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine.create_entry(root, new_entry("a", "p")).expect("ce");
    let observer = install_observer(&mut engine);
    engine
        .attach_file(uuid, "x.txt", b"hello".to_vec())
        .expect("attach");
    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::AttachmentsChanged(v) => assert_eq!(v, &vec![uuid]),
        other => panic!("expected AttachmentsChanged, got {other:?}"),
    }
}

#[test]
fn set_tags_event_shape() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine.create_entry(root, new_entry("a", "p")).expect("ce");
    let observer = install_observer(&mut engine);
    engine
        .set_tags(uuid, vec!["work".into(), "secret".into()])
        .expect("tags");
    let events = observer.snapshot();
    // Two events: TagsChanged + EntriesUpdated. The tag index changed
    // independently of the entry row mutation, so we fire both.
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], ChangeEvent::TagsChanged(ref v) if v == &vec![uuid]));
    assert!(matches!(events[1], ChangeEvent::EntriesUpdated(ref v) if v == &vec![uuid]));
}

#[test]
fn group_mutations_emit_group_events() {
    let (mut engine, root, _dir) = vault_with_recycle_bin();
    let observer = install_observer(&mut engine);
    let a = engine.create_group(root, new_group("a")).expect("ca");
    let b = engine.create_group(root, new_group("b")).expect("cb");
    let upd = keys_engine::GroupUpdate {
        name: Some("a2".into()),
        ..keys_engine::GroupUpdate::default()
    };
    engine.update_group(a, upd).expect("update");
    engine.recycle_group(a).expect("recycle");
    engine.restore_group(a, b).expect("restore (also a move)");
    engine.move_group(a, root).expect("move");
    let events = observer.snapshot();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::GroupsAdded(v) if v == &vec![a]))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::GroupsAdded(v) if v == &vec![b]))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::GroupsUpdated(v) if v == &vec![a]))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::GroupsRecycled(v) if v == &vec![a]))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::GroupsRestored(v) if v == &vec![a]))
    );
    assert!(events.iter().any(|e| matches!(
        e,
        ChangeEvent::GroupsMoved(v) if v.iter().any(|m| m.uuid == a && m.to_parent == root)
    )));
}

#[test]
fn delete_group_with_descendants_emits_combined() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let parent = engine.create_group(root, new_group("p")).expect("cg p");
    let child = engine
        .create_group(parent, new_group("c"))
        .expect("cg child");
    let e1 = engine
        .create_entry(parent, new_entry("e1", "p"))
        .expect("ce1");
    let e2 = engine
        .create_entry(child, new_entry("e2", "p"))
        .expect("ce2");
    let observer = install_observer(&mut engine);
    engine.delete_group(parent).expect("delete cascade");
    let events = observer.snapshot();
    // Expect exactly two events: EntriesDeleted (covering e1 + e2) and
    // GroupsDeleted (covering parent + child).
    assert_eq!(events.len(), 2);
    match &events[0] {
        ChangeEvent::EntriesDeleted(v) => {
            let uuids: Vec<Uuid> = v.iter().map(|i| i.uuid).collect();
            assert!(uuids.contains(&e1) && uuids.contains(&e2), "got {uuids:?}");
            assert_eq!(v.len(), 2);
            // The entry that lived in `child` carries `previous_group =
            // child`; the entry in `parent` carries `previous_group =
            // parent`. Order is leaves-up, so child's entry fires first.
            let e1_info = v.iter().find(|i| i.uuid == e1).unwrap();
            let e2_info = v.iter().find(|i| i.uuid == e2).unwrap();
            assert_eq!(e1_info.previous_group, parent);
            assert_eq!(e2_info.previous_group, child);
        }
        other => panic!("expected EntriesDeleted, got {other:?}"),
    }
    match &events[1] {
        ChangeEvent::GroupsDeleted(v) => {
            assert_eq!(v.len(), 2);
            let uuids: Vec<Uuid> = v.iter().map(|i| i.uuid).collect();
            assert!(uuids.contains(&parent) && uuids.contains(&child));
            let child_info = v.iter().find(|i| i.uuid == child).unwrap();
            let parent_info = v.iter().find(|i| i.uuid == parent).unwrap();
            assert_eq!(child_info.previous_parent, Some(parent));
            assert_eq!(parent_info.previous_parent, Some(root));
        }
        other => panic!("expected GroupsDeleted, got {other:?}"),
    }
}

#[test]
fn no_observer_set_means_no_events_captured() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    // Don't install an observer; just exercise a mutation and assert
    // nothing blows up. The Option<Arc<dyn>> path is exercised by every
    // pre-observer call above (e.g. the `engine_with_empty_vault`
    // bootstrap ingests without one) but this test is explicit.
    let uuid = engine.create_entry(root, new_entry("a", "p")).expect("ce");
    let _ = uuid;
    let observer = install_observer(&mut engine);
    engine.clear_observer();
    let _ = engine
        .create_entry(root, new_entry("b", "p"))
        .expect("ce after clear");
    // Observer was installed but then cleared before the second create —
    // it should have captured nothing.
    assert!(observer.snapshot().is_empty());
}

#[test]
fn smart_folder_crud_emits_events() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let observer = install_observer(&mut engine);
    let id = engine
        .create_smart_folder("recent", &Predicate::Expired)
        .expect("create sf");
    engine
        .update_smart_folder(id, "renamed", &Predicate::Expired)
        .expect("update sf");
    engine.delete_smart_folder(id).expect("delete sf");
    let events = observer.snapshot();
    assert_eq!(events.len(), 3);
    assert!(matches!(events[0], ChangeEvent::SmartFolderCreated(i) if i == id));
    assert!(matches!(events[1], ChangeEvent::SmartFolderUpdated(i) if i == id));
    assert!(matches!(events[2], ChangeEvent::SmartFolderDeleted(i) if i == id));
}

#[test]
fn save_to_kdbx_emits_save_completed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = fresh_kdbx(protector());
    let mut engine =
        Engine::open(&db_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    let observer = install_observer(&mut engine);
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save");
    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], ChangeEvent::SaveCompleted));
}

#[test]
fn ingest_from_kdbx_emits_bulk_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = build_bulk_kdbx(/* groups */ 5, /* entries */ 10);
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    let observer = install_observer(&mut engine);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    let events = observer.snapshot();
    // Exactly one of each — GroupsAdded then EntriesAdded.
    assert_eq!(events.len(), 2);
    match &events[0] {
        ChangeEvent::GroupsAdded(v) => assert_eq!(v.len(), 1 + 5), // root + 5
        other => panic!("expected GroupsAdded, got {other:?}"),
    }
    match &events[1] {
        ChangeEvent::EntriesAdded(v) => assert_eq!(v.len(), 10),
        other => panic!("expected EntriesAdded, got {other:?}"),
    }
}

#[test]
fn failed_mutation_does_not_emit() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let observer = install_observer(&mut engine);
    // Update a uuid that doesn't exist.
    let bogus = Uuid::new_v4();
    let upd = EntryUpdate {
        title: Some("x".into()),
        ..EntryUpdate::default()
    };
    let err = engine.update_entry(bogus, upd).unwrap_err();
    let _ = err; // expected NotFound
    assert!(observer.snapshot().is_empty());
}

#[test]
fn emit_happens_after_commit() {
    // Observer that queries the engine state by re-opening the DB on
    // the side. Verifies that by the time `on_event` fires, the
    // mutation is durable. We use a sentinel that gets bumped whenever
    // the observer successfully sees the new row.
    #[derive(Debug)]
    struct VerifyObserver {
        db_path: std::path::PathBuf,
        title: String,
        saw_row: Mutex<bool>,
    }
    impl DataChangeObserver for VerifyObserver {
        fn on_event(&self, _event: ChangeEvent) {
            let conn = rusqlite::Connection::open(&self.db_path).expect("reopen");
            let mut hex = String::with_capacity(64);
            for b in &DB_KEY_BYTES {
                use std::fmt::Write as _;
                write!(&mut hex, "{b:02x}").expect("hex");
            }
            conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))
                .expect("apply key");
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM entry WHERE title = ?1",
                    rusqlite::params![&self.title],
                    |r| r.get(0),
                )
                .expect("count");
            if count > 0 {
                *self.saw_row.lock().unwrap() = true;
            }
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id.0;
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let observer = Arc::new(VerifyObserver {
        db_path: path.clone(),
        title: "after-commit-marker".into(),
        saw_row: Mutex::new(false),
    });
    engine.set_observer(observer.clone());
    let mut fields = new_entry("after-commit-marker", "p");
    fields.title = "after-commit-marker".into();
    let _ = engine.create_entry(root, fields).expect("create");
    assert!(
        *observer.saw_row.lock().unwrap(),
        "observer fired before the new row was visible to another connection"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Build an engine where the vault carries a recycle bin group. The
/// keepass-core `create_empty_v4` factory does not install a recycle
/// bin by default, and several mutation paths refuse to recycle without
/// one, so we splice one in before ingest.
fn vault_with_recycle_bin() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let bin_uuid = Uuid::new_v4();
    let mut vault = kdbx.vault().clone();
    vault.root.groups.push(Group::empty(GroupId(bin_uuid)));
    vault.meta.recycle_bin_uuid = Some(GroupId(bin_uuid));
    vault.meta.recycle_bin_enabled = true;
    let root_uuid = vault.root.id.0;
    kdbx.replace_vault(vault);
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, root_uuid, dir)
}

/// Build a KDBX with `group_count` subgroups under the root, each
/// holding `entries_per_group_rounded` entries totalling `entry_count`.
fn build_bulk_kdbx(group_count: usize, entry_count: usize) -> Kdbx<Unlocked> {
    let mut kdbx = fresh_kdbx(protector());
    let mut vault = kdbx.vault().clone();
    for i in 0..group_count {
        let mut g = Group::empty(GroupId(Uuid::new_v4()));
        g.name = format!("g{i}");
        vault.root.groups.push(g);
    }
    for i in 0..entry_count {
        let mut entry = Entry::empty(EntryId(Uuid::new_v4()));
        entry.title = format!("e{i}");
        vault.root.entries.push(entry);
    }
    kdbx.replace_vault(vault);
    kdbx
}
