//! Integration tests for the external-change reconcile path.
//!
//! Covers [`Engine::reconcile_with_disk_park_conflicts`] end to end:
//! one-sided auto-merge, genuine-conflict hold (owner rows), the
//! `needs_write_back` loop-safety contract on both ends, and a full
//! file-watcher round-trip.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewEntry;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    ChangeEvent, DataChangeObserver, DbKey, Engine, KeyProvider, KeyProviderError,
    NotifyFileWatcher, ParkConflictsResult,
};
use secrecy::{ExposeSecret, SecretString};

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

// ── Owner-rows park path (Phase 4) ──────────────────────────────────────
//
// The live sync path is `reconcile_with_disk_park_conflicts`, now backed by
// the owner-rows ingest. Re-prove the two ends of its loop-safety contract on
// the same fixture the classic-path tests use.

/// A one-sided external **password** edit propagates through the owner-rows
/// park path: only the peer moved off the shared ancestor, so `classify`
/// auto-merges and the local side advances ⇒ `Applied`. (Bug #1 class: the
/// old cheap-equivalence comparator ignored password-only edits.)
#[test]
fn park_one_sided_password_edit_auto_merges_and_advances() {
    let mut f = fixture();
    let seed_uuid = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // Disk: edit ONLY the password (local stays on the shared ancestor).
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| e.set_password(SecretString::from("disk-only-pw".to_string())),
        )
        .expect("disk pw edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    match result {
        ParkConflictsResult::Applied {
            applied, parked, ..
        } => {
            assert_eq!(applied.entries_updated, 1, "the peer edit advanced local");
            assert!(
                parked.entries_with_parked_conflict.is_empty(),
                "a one-sided edit is not a conflict",
            );
        }
        other => panic!("expected Applied, got {other:?}"),
    }

    // The password landed locally, and nothing is badged.
    let revealed = f.engine.reveal_password(seed_uuid).expect("reveal");
    assert_eq!(revealed.expose_secret(), "disk-only-pw");
    assert!(
        f.engine
            .entries_with_parked_conflict()
            .expect("query")
            .is_empty(),
    );
}

/// A genuine concurrent edit (both sides moved the same entry off the shared
/// ancestor) holds open: nothing advances locally ⇒ `NoChange`, a peer
/// conflict row is stored, and the entry is badged. This is the structural
/// loop-safety guarantee — no local advance ⇒ no save ⇒ no re-push.
#[test]
fn park_genuine_concurrent_edit_holds_and_stores_row() {
    let mut f = fixture();
    let seed_uuid = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // Local edit + concurrent disk edit of the SAME entry's title.
    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                title: Some("local-rename".into()),
                ..Default::default()
            },
        )
        .expect("local edit");
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| e.set_title("disk-rename"),
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(
        matches!(result, ParkConflictsResult::NoChange),
        "a held conflict advances nothing ⇒ NoChange (loop-safe), got {result:?}",
    );

    // The owner row drives the badge; local kept its own value.
    assert_eq!(
        f.engine.entries_with_parked_conflict().expect("query"),
        vec![seed_uuid],
        "the conflict row is stored and badged",
    );
    let after = f.engine.entry(seed_uuid).expect("entry").expect("present");
    assert_eq!(after.title, "local-rename", "hold-open keeps local's title");
}

/// A pure disk-side edit, once adopted, leaves the merged local state
/// content-digest-equal to the file that delivered it — so `Applied`
/// reports `needs_write_back: false`. This is the write-back
/// convergence guard: a client that saves here anyway churns the file's
/// mtime for nothing (and between two rewrite-on-ingest clients sharing
/// a vault over a file-sync transport, would ping-pong forever).
#[test]
fn park_one_sided_disk_edit_needs_no_write_back() {
    let mut f = fixture();
    let seed_uuid = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // Disk: a title edit local never saw. Local stays on the ancestor.
    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| e.set_title("disk-rename"),
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    match result {
        ParkConflictsResult::Applied {
            applied,
            needs_write_back,
            ..
        } => {
            assert_eq!(applied.entries_updated, 1, "the disk edit advanced local");
            assert!(
                !needs_write_back,
                "adopting a one-way ingest converges onto the file — nothing to push back",
            );
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

/// A genuine two-sided merge — local holds an unsaved edit while the
/// disk file brings independent news — leaves the merged state holding
/// content the file lacks, so `Applied` reports
/// `needs_write_back: true`: the file peer's only transport is a
/// client write-back, and exactly one save converges the pair.
#[test]
fn park_two_sided_merge_needs_write_back() {
    let mut f = fixture();
    let seed_uuid = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // Local: an unsaved username edit (mirror only, not on disk).
    f.engine
        .update_entry(
            seed_uuid,
            keys_engine::EntryUpdate {
                username: Some("local-user".into()),
                ..Default::default()
            },
        )
        .expect("local edit");

    // Disk: an independent new entry (no overlap with the local edit).
    let mut external = reopen_kdbx(&f.kdbx_path);
    let root = external.vault().root.id;
    external
        .add_entry(root, NewEntry::new("disk-addition"))
        .expect("disk add");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    match result {
        ParkConflictsResult::Applied {
            applied,
            needs_write_back,
            ..
        } => {
            assert_eq!(applied.entries_added, 1, "the disk addition advanced local");
            assert!(
                needs_write_back,
                "the merged state holds a local edit the file lacks — push it back",
            );
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

#[test]
fn reconcile_round_trip_with_file_watcher() {
    // End-to-end: real NotifyFileWatcher fires when the disk file is
    // mutated externally; the watcher's reconcile-trigger drives a
    // call into `reconcile_with_disk_park_conflicts`; the observer
    // captures the resulting `ExternalChangeMerged` event.
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

    // We can't call `engine.reconcile_with_disk_park_conflicts` directly from a
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
        .reconcile_with_disk_park_conflicts(&kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(
        matches!(result, ParkConflictsResult::Applied { .. }),
        "expected Applied from watcher-driven reconcile, got {result:?}",
    );
    let events = observer.snapshot();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::ExternalChangeMerged { .. })),
        "expected ExternalChangeMerged event",
    );
}

/// ARC C watermark semantics, direction 1: adopting a one-sided disk
/// edit into a CLEAN mirror is a digest-proven correspondence point —
/// the engine settles the persistence watermark itself, so a
/// save-iff-dirty orchestrator won't rewrite identical bytes (mtime
/// churn, the reconcile ping-pong seed).
#[test]
fn digest_equal_adoption_settles_a_clean_mirror() {
    let mut f = fixture();
    f.engine
        .record_kdbx_state_signature(&f.kdbx_path)
        .expect("settle");
    assert!(!f.engine.persistence_state().expect("state").is_dirty());
    let seed_uuid = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| e.set_title("disk-rename"),
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(
        matches!(
            result,
            ParkConflictsResult::Applied {
                needs_write_back: false,
                ..
            }
        ),
        "one-sided adoption should be digest-equal, got {result:?}"
    );
    assert!(
        !f.engine.persistence_state().expect("state").is_dirty(),
        "a clean mirror adopting a one-sided disk edit must settle — \
         flushing here would rewrite identical bytes"
    );
}

/// ARC C watermark semantics, direction 2 (the data-loss guard): the
/// content digest deliberately excludes history/timestamps, so
/// digest-equality can NEVER prove a pending digest-invisible local
/// change (here: a last-accessed touch) reached the file. A mirror
/// that was dirty going into the reconcile must come out dirty, or the
/// pending change silently dies at the next mirror rebuild.
#[test]
fn digest_equal_adoption_never_settles_over_pending_local_change() {
    let mut f = fixture();
    f.engine
        .record_kdbx_state_signature(&f.kdbx_path)
        .expect("settle");
    let seed_uuid = f
        .engine
        .list_entries(None, keys_engine::Pagination::all())
        .expect("list")[0]
        .uuid;

    // Digest-invisible local change: accessed_at projects into the
    // KDBX but is outside the digest's scope.
    f.engine.touch_entry(seed_uuid).expect("touch");
    assert!(
        f.engine.persistence_state().expect("state").is_dirty(),
        "the touch must owe a write"
    );

    let mut external = reopen_kdbx(&f.kdbx_path);
    external
        .edit_entry(
            keepass_core::model::EntryId(seed_uuid),
            keepass_core::model::HistoryPolicy::Snapshot,
            |e| e.set_title("disk-rename"),
        )
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("reconcile");
    assert!(
        matches!(
            result,
            ParkConflictsResult::Applied {
                needs_write_back: false,
                ..
            }
        ),
        "the touch is digest-invisible, so this still reads digest-equal, got {result:?}"
    );
    assert!(
        f.engine.persistence_state().expect("state").is_dirty(),
        "a dirty mirror must stay dirty through a digest-equal adoption — \
         settling would silently drop the pending change"
    );
}
