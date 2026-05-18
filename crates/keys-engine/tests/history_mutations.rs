//! Integration tests for [`Engine::delete_history_at`] (6.17-H follow-up,
//! unblocks the 6.17-I legacy-vault deletion slice on Keys-Mac).

use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    ChangeEvent, DataChangeObserver, DbKey, Engine, EngineError, KeyProvider, KeyProviderError,
};
use uuid::Uuid;

// ── test wiring (same shape as tests/history.rs) ──────────────────────

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

const SESSION_KEY_BYTES: [u8; 32] = [0x6c; 32];
const DB_KEY_BYTES: [u8; 32] = [0x42; 32];

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector())).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
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

/// Build an engine pre-populated with one entry carrying three history
/// snapshots (`v0`, `v1`, `v2`; live row is `v3`). Returns
/// `(engine, entry_uuid, tempdir)`.
fn engine_with_history() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("v0")).expect("add");
    for label in ["v1", "v2", "v3"] {
        let owned = label.to_owned();
        kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
            e.set_title(&owned);
        })
        .expect("edit");
    }
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, id.0, dir)
}

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn delete_history_at_removes_only_named_snapshot() {
    let (mut engine, id, _dir) = engine_with_history();

    // Sanity: three snapshots, live entry is `v3`.
    let before = engine.history(id).expect("history");
    assert_eq!(before.len(), 3);
    assert_eq!(before[0].title, "v0");
    assert_eq!(before[1].title, "v1");
    assert_eq!(before[2].title, "v2");
    let live_before = engine.entry(id).expect("entry").expect("present");
    assert_eq!(live_before.title, "v3");
    let modified_before = live_before.modified_at;

    engine.delete_history_at(id, 1).expect("delete");

    let after = engine.history(id).expect("history");
    assert_eq!(after.len(), 2);
    // Surviving snapshots renumber to a dense 0..N: `v0` stays at 0,
    // `v2` shifts down from 2 to 1.
    assert_eq!(after[0].history_index, 0);
    assert_eq!(after[0].title, "v0");
    assert_eq!(after[1].history_index, 1);
    assert_eq!(after[1].title, "v2");

    // Live entry is untouched — title and modified_at both unchanged.
    let live_after = engine.entry(id).expect("entry").expect("present");
    assert_eq!(live_after.title, "v3");
    assert_eq!(
        live_after.modified_at, modified_before,
        "deleting a history snapshot must not bump entry.modified_at",
    );
}

#[test]
fn delete_history_at_emits_entries_updated() {
    let (mut engine, id, _dir) = engine_with_history();
    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());

    engine.delete_history_at(id, 0).expect("delete");

    let events = observer.snapshot();
    assert_eq!(
        events.len(),
        1,
        "expected exactly one event, got {events:?}"
    );
    match &events[0] {
        ChangeEvent::EntriesUpdated(v) => assert_eq!(v, &vec![id]),
        other => panic!("expected EntriesUpdated([{id}]), got {other:?}"),
    }
}

#[test]
fn delete_history_at_unknown_entry_returns_not_found_entry() {
    let (mut engine, _id, _dir) = engine_with_history();
    let err = engine
        .delete_history_at(Uuid::new_v4(), 0)
        .expect_err("missing entry should error");
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, "entry"),
        other => panic!("expected NotFound {{ entity: \"entry\" }}, got {other:?}"),
    }
}

#[test]
fn delete_history_at_oob_index_returns_not_found_history_snapshot() {
    let (mut engine, id, _dir) = engine_with_history();
    let err = engine
        .delete_history_at(id, 99)
        .expect_err("OOB index should error");
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, "history_snapshot"),
        other => panic!("expected NotFound {{ entity: \"history_snapshot\" }}, got {other:?}"),
    }
    // The pre-existing snapshots are untouched after a failed delete.
    let history = engine.history(id).expect("history");
    assert_eq!(history.len(), 3);
}

#[test]
fn delete_history_at_last_snapshot_leaves_empty_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("v0")).expect("add");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("v1");
    })
    .expect("edit");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    assert_eq!(engine.history(id.0).expect("history").len(), 1);
    engine.delete_history_at(id.0, 0).expect("delete");
    assert!(engine.history(id.0).expect("history").is_empty());
}
