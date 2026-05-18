//! Integration tests for Phase 4 task 4.6 — external-change merge.
//!
//! Covers [`Engine::reconcile_with_disk`] end to end: `NoChange`,
//! adds/updates/deletes from disk, conflict surfacing, event
//! emission, transaction atomicity on failure, common-ancestor
//! refresh, and a full file-watcher round-trip.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{NewEntry, NewGroup};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    ChangeEvent, DataChangeObserver, DbKey, Engine, KeyProvider, KeyProviderError, MergeResult,
    NotifyFileWatcher,
};

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
const PASSWORD: &[u8] = b"pw";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(PASSWORD)
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), "test", Some(protector())).expect("create")
}

fn reopen_kdbx(path: &std::path::Path) -> Kdbx<Unlocked> {
    Kdbx::open(path)
        .expect("open kdbx")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock kdbx")
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

#[derive(Debug)]
struct ChannelTrigger(Mutex<std::sync::mpsc::Sender<()>>);

impl keys_engine::ReconcileTrigger for ChannelTrigger {
    fn trigger(&self) {
        let _ = self.0.lock().unwrap().send(());
    }
}

/// Spin up an engine + KDBX file on disk seeded with one entry under
/// the root group, so reconcile has something to merge against.
struct Fixture {
    _dir: tempfile::TempDir,
    kdbx_path: std::path::PathBuf,
    engine: Engine,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("seed"))
        .expect("seed entry");
    let mut engine =
        Engine::open(&db_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    // Save, then re-open the saved file and re-ingest so SQLite
    // timestamps match the on-disk (second-precision) timestamps.
    // Without this, the engine's projection carries sub-second
    // precision that disk-round-tripped entries don't, so the
    // merge sees a phantom timestamp divergence on every entry.
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("initial save");
    let kdbx_reread = reopen_kdbx(&kdbx_path);
    engine
        .ingest_from_kdbx(&kdbx_reread)
        .expect("re-ingest from disk");
    let _ = (db_path, kdbx);
    Fixture {
        _dir: dir,
        kdbx_path,
        engine,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn reconcile_no_change_returns_nochange() {
    let mut f = fixture();
    let result = f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");
    assert!(
        matches!(result, MergeResult::NoChange),
        "engine + disk in sync after save → NoChange, got {result:?}"
    );
}

#[test]
fn reconcile_adds_external_entry() {
    let mut f = fixture();

    // External: open the kdbx file, add an entry, save it back.
    let mut external = reopen_kdbx(&f.kdbx_path);
    let root = external.vault().root.id;
    let new_id = external
        .add_entry(root, NewEntry::new("from-disk"))
        .expect("add external");
    let bytes = external.save_to_bytes().expect("save_to_bytes");
    std::fs::write(&f.kdbx_path, &bytes).expect("write disk");

    let result = f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");

    match result {
        MergeResult::Merged { applied } => {
            assert_eq!(applied.entries_added, 1, "one entry added");
        }
        other => panic!("expected Merged, got {other:?}"),
    }

    // Round-trip via SQLite: the new entry is now visible.
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list entries");
    assert!(
        summaries.iter().any(|s| s.uuid == new_id.0),
        "added entry should appear in list_entries",
    );
}

#[test]
fn reconcile_adds_external_group() {
    let mut f = fixture();

    let mut external = reopen_kdbx(&f.kdbx_path);
    let root = external.vault().root.id;
    let new_group_id = external
        .add_group(root, NewGroup::new("Logins-on-disk"))
        .expect("add group");
    let bytes = external.save_to_bytes().expect("save_to_bytes");
    std::fs::write(&f.kdbx_path, &bytes).expect("write disk");

    let result = f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");
    match result {
        MergeResult::Merged { applied } => {
            assert_eq!(applied.groups_added, 1, "one group added");
        }
        other => panic!("expected Merged, got {other:?}"),
    }

    let groups = f.engine.group_tree().expect("group_tree");
    assert!(
        groups.iter().any(|g| g.uuid == new_group_id.0),
        "added group should appear in group_tree",
    );
}

#[test]
fn reconcile_deletes_locally_when_disk_deletes() {
    let mut f = fixture();
    // Find the seed entry uuid.
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .delete_entry(keepass_core::model::EntryId(seed_uuid))
        .expect("delete on disk");
    let bytes = external.save_to_bytes().expect("save_to_bytes");
    std::fs::write(&f.kdbx_path, &bytes).expect("write disk");

    let result = f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");
    match result {
        MergeResult::Merged { applied } => {
            assert_eq!(applied.entries_deleted, 1, "one entry deleted");
        }
        other => panic!("expected Merged, got {other:?}"),
    }
    let after = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list after");
    assert!(
        !after.iter().any(|s| s.uuid == seed_uuid),
        "deleted entry should be gone from SQLite",
    );
}

#[test]
fn reconcile_updates_when_disk_updates() {
    let mut f = fixture();
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    // External: tweak the entry's title.
    let mut external = reopen_kdbx(&f.kdbx_path);
    {
        let root = external.vault().root.id;
        external
            .edit_entry(
                keepass_core::model::EntryId(seed_uuid),
                keepass_core::model::HistoryPolicy::Snapshot,
                |e| {
                    e.set_title("renamed-on-disk");
                },
            )
            .expect("edit entry");
        let _ = root;
    }
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");
    match result {
        MergeResult::Merged { applied } => {
            assert_eq!(applied.entries_updated, 1, "one entry updated");
        }
        other => panic!("expected Merged, got {other:?}"),
    }
    let after = f.engine.entry(seed_uuid).expect("entry").expect("present");
    assert_eq!(after.title, "renamed-on-disk");
}

#[test]
fn reconcile_detects_conflict_on_field() {
    let mut f = fixture();
    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;

    // Local edit via the engine.
    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-rename".into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    // Disk edit via keepass-core.
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| {
                e.set_title("disk-rename");
            },
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");
    match result {
        MergeResult::Conflict(payload) => {
            assert_eq!(payload.entry_conflicts.len(), 1, "one entry conflict");
            let c = &payload.entry_conflicts[0];
            assert_eq!(c.entry_id.0, seed_uuid);
            assert!(
                c.field_deltas.iter().any(|d| d.key == "Title"),
                "conflict surfaces the Title field delta",
            );
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
    assert_eq!(
        f.engine.pending_conflict_count_for_test(),
        1,
        "conflict payload stashed on engine",
    );
}

#[test]
fn reconcile_emits_external_change_merged_event() {
    let mut f = fixture();
    let observer = Arc::new(CaptureObserver::default());
    f.engine.set_observer(observer.clone());

    let mut external = reopen_kdbx(&f.kdbx_path);
    let root = external.vault().root.id;
    external
        .add_entry(root, NewEntry::new("from-disk"))
        .expect("add");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    f.engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");

    let events = observer.snapshot();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::ExternalChangeMerged { .. })),
        "expected ExternalChangeMerged in {events:?}",
    );
}

#[test]
fn reconcile_emits_conflict_detected_event() {
    let mut f = fixture();
    let observer = Arc::new(CaptureObserver::default());
    f.engine.set_observer(observer.clone());

    let summaries = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list");
    let seed_uuid = summaries[0].uuid;
    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local".into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    // Discard the EntriesUpdated event that arrived during the local
    // edit so we can assert the next observer call is the conflict.
    observer.events.lock().unwrap().clear();

    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| {
                e.set_title("disk");
            },
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    f.engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");

    let events = observer.snapshot();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::ConflictDetected(_))),
        "expected ConflictDetected in {events:?}",
    );
}

#[test]
fn reconcile_atomic_on_failure() {
    // Induce a failure by pointing reconcile at a non-existent kdbx
    // path: the disk-read step fails before any SQLite mutation.
    // SQLite state must be unchanged.
    let mut f = fixture();
    let before = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list before");
    let bogus = f.kdbx_path.with_file_name("does-not-exist.kdbx");
    let result = f.engine.reconcile_with_disk(&bogus, &composite());
    assert!(result.is_err(), "reconcile should fail on missing file");
    let after = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list after");
    assert_eq!(
        before.len(),
        after.len(),
        "no SQLite mutation on reconcile failure",
    );
}

#[test]
fn reconcile_updates_common_ancestor_after_success() {
    let mut f = fixture();

    // Make an external change so reconcile takes the apply path.
    let mut external = reopen_kdbx(&f.kdbx_path);
    let root = external.vault().root.id;
    external
        .add_entry(root, NewEntry::new("from-disk"))
        .expect("add");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    f.engine
        .reconcile_with_disk(&f.kdbx_path, &composite())
        .expect("reconcile");

    let stored = f
        .engine
        .last_saved_kdbx_bytes()
        .expect("query")
        .expect("ancestor stored");
    let on_disk = std::fs::read(&f.kdbx_path).expect("read kdbx");
    assert_eq!(
        stored, on_disk,
        "common ancestor must match disk bytes after Merged",
    );
}

#[test]
fn reconcile_round_trip_with_file_watcher() {
    // End-to-end: real NotifyFileWatcher fires when the disk file is
    // mutated externally; the watcher's reconcile-trigger drives a
    // call into `reconcile_with_disk`; the observer captures the
    // resulting `ExternalChangeMerged` event.
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("seed")).expect("seed");

    let watcher: Arc<dyn keys_engine::FileWatcher> =
        Arc::new(NotifyFileWatcher::new(kdbx_path.clone()).expect("watcher"));

    let mut engine = Engine::open(
        &db_path,
        &FixedKey(DB_KEY_BYTES),
        protector(),
        Some(Arc::clone(&watcher)),
    )
    .expect("open engine");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("initial save");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());

    // We can't call `engine.reconcile_with_disk` directly from a
    // ReconcileTrigger because the engine is owned outside the
    // trigger. Use a channel: the trigger pushes a "go" signal, the
    // test thread drains it and calls reconcile on the engine.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    engine.set_reconcile_trigger(Arc::new(ChannelTrigger(Mutex::new(tx))));

    // External edit: open the kdbx, add an entry, write the bytes.
    let mut external = reopen_kdbx(&kdbx_path);
    let ext_root = external.vault().root.id;
    external
        .add_entry(ext_root, NewEntry::new("ext"))
        .expect("ext add");
    let bytes = external.save_to_bytes().expect("save");
    // Replace, not "rename over" — the watcher will see a Modify event.
    std::fs::write(&kdbx_path, &bytes).expect("write");

    // Wait for the trigger to fire (give the watcher a generous window).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut got_signal = false;
    while std::time::Instant::now() < deadline {
        if rx.recv_timeout(Duration::from_millis(200)).is_ok() {
            got_signal = true;
            break;
        }
    }
    assert!(got_signal, "file watcher trigger did not fire in time");

    // Drain any further triggers before reconciling.
    while rx.try_recv().is_ok() {}

    let result = engine
        .reconcile_with_disk(&kdbx_path, &composite())
        .expect("reconcile");
    assert!(
        matches!(result, MergeResult::Merged { .. }),
        "expected Merged from watcher-driven reconcile, got {result:?}",
    );
    let events = observer.snapshot();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::ExternalChangeMerged { .. })),
        "expected ExternalChangeMerged event",
    );
}
