//! Integration tests for the [`keys_ffi::Engine`] FFI surface.

#![allow(clippy::doc_markdown)]
//!
//! Exercises the FFI shape directly via the Rust-side `Arc<dyn …>`
//! trait objects — uniffi's foreign-binding generation is out of scope
//! here (5.5 lands the Swift regen). These tests verify:
//!
//! - construction / close round-trips
//! - read methods return the expected Records
//! - mutation methods accept Records and return UUIDs
//! - reveal_password returns plaintext as a String
//! - observer bridge delivers events
//! - file-watcher bridge round-trips a synthetic event
//! - error mapping (WrongKey, NotFound, ResolutionMismatch)
//! - the four async slow ops (ingest, save, reconcile) complete
//! - Predicate FFI mirror round-trips through the engine
//! - conflict resolution end-to-end via the FFI surface

use std::sync::{Arc, Mutex};

use keys_ffi::{
    ChangeEvent, Engine, EngineError, FileWatcherEvent, IconRef, NewEntryFields, NewGroupFields,
    Page, Predicate, VaultDataChangeObserver, VaultDbKeyProvider, VaultDbKeyProviderError,
    VaultFieldProtector, VaultFileWatcher, VaultFileWatcherObserver, VaultProtectorError,
};

const DB_KEY: [u8; 32] = [0x42; 32];
const SESSION_KEY: [u8; 32] = [0x9c; 32];
const KDBX_PASSWORD: &str = "test-password";

struct FixedDbKey;
impl VaultDbKeyProvider for FixedDbKey {
    fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
        Ok(DB_KEY.to_vec())
    }
}

struct WrongDbKey;
impl VaultDbKeyProvider for WrongDbKey {
    fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
        Ok([0u8; 32].to_vec())
    }
}

struct FailingDbKey;
impl VaultDbKeyProvider for FailingDbKey {
    fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
        Err(VaultDbKeyProviderError::KeyUnavailable(
            "synthetic keychain-locked failure".into(),
        ))
    }
}

struct FixedProtector;
impl VaultFieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
        Ok(SESSION_KEY.to_vec())
    }
}

fn open_fresh_engine(db_path: &std::path::Path) -> Arc<Engine> {
    Engine::open(
        db_path.to_string_lossy().into_owned(),
        Arc::new(FixedDbKey),
        Arc::new(FixedProtector),
        None,
    )
    .expect("open engine")
}

/// Build a fresh KDBX file on disk via keys-engine's own keepass-core
/// helpers. Returns the path.
fn seed_kdbx(path: &std::path::Path) {
    use keepass_core::CompositeKey;
    use keepass_core::kdbx::Kdbx;
    use keepass_core::model::{NewEntry, NewGroup};
    use secrecy::SecretString;
    let composite = CompositeKey::from_password(KDBX_PASSWORD.as_bytes());
    let mut kdbx = Kdbx::create_empty_v4(&composite, "test").expect("create");
    let root = kdbx.vault().root.id;
    let logins = kdbx
        .add_group(root, NewGroup::new("Logins"))
        .expect("add group");
    kdbx.add_entry(
        logins,
        NewEntry::new("acme")
            .username("alice")
            .url("https://example.com/")
            .password(SecretString::from("Tr0ub4dor&3")),
    )
    .expect("add entry");
    let bytes = kdbx.save_to_bytes().expect("save bytes");
    std::fs::write(path, bytes).expect("write");
}

#[test]
fn engine_open_close_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let engine = open_fresh_engine(&db_path);
    engine.close().expect("close ok");
    // Idempotent — close again
    engine.close().expect("close idempotent");
    // Reads after close should fail with NotFound { entity = "engine" }
    let err = engine.group_tree().expect_err("read after close fails");
    matches!(err, EngineError::NotFound { ref entity } if entity == "engine")
        .then_some(())
        .expect("NotFound engine");
}

/// Regression: when a foreign-implemented `VaultDbKeyProvider` throws
/// `KeyUnavailable`, uniffi must be able to **lift** the error across
/// the FFI boundary. Prior to removing `#[uniffi(flat_error)]` from
/// `VaultDbKeyProviderError`, this path panicked at runtime with
/// "Can't lift flat errors" — flat-error enums can only be lowered
/// (Rust-throws-to-foreign), not lifted (foreign-throws-to-Rust).
///
/// The bug was latent because in-process Rust callers like this test
/// also exercise the lift path via the `BridgeDbKeyProvider` adapter,
/// so a regression here catches it without needing the full Swift
/// round-trip. The original panic surfaced from the macOS app's
/// xcodebuild sandbox where the Keychain write was denied and the
/// Swift `SqliteKeyProvider` threw `KeyUnavailable`.
#[test]
fn engine_open_surfaces_db_key_provider_failure() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let err = Engine::open(
        db_path.to_string_lossy().into_owned(),
        Arc::new(FailingDbKey),
        Arc::new(FixedProtector),
        None,
    )
    .expect_err("open must surface the provider failure, not panic");
    match err {
        EngineError::KeyProvider(msg) => {
            assert!(
                msg.contains("synthetic keychain-locked failure"),
                "key-provider error must carry the implementation-supplied detail; got: {msg}",
            );
        }
        other => panic!("expected EngineError::KeyProvider, got {other:?}"),
    }
}

#[test]
fn engine_error_mapping_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    // First open with FixedDbKey to create + bind a key
    let engine = open_fresh_engine(&db_path);
    engine.close().expect("close");
    // Try to reopen with the wrong key
    let err = Engine::open(
        db_path.to_string_lossy().into_owned(),
        Arc::new(WrongDbKey),
        Arc::new(FixedProtector),
        None,
    )
    .expect_err("must fail");
    assert!(matches!(err, EngineError::WrongKey), "got {err:?}");
}

#[test]
fn engine_error_mapping_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let engine = open_fresh_engine(&db_path);
    // Well-formed UUID but no row → engine returns Ok(None) for entry()
    let nil = uuid::Uuid::nil().to_string();
    let result = engine.entry(nil).expect("query ok");
    assert!(result.is_none());
    // Malformed UUID surfaces as NotFound { entity = "entry" }
    let err = engine
        .entry("not-a-uuid".to_owned())
        .expect_err("must fail");
    matches!(err, EngineError::NotFound { ref entity } if entity == "entry")
        .then_some(())
        .expect("NotFound entry");
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_async_ingest_completes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    seed_kdbx(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    engine
        .ingest_from_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("ingest");
    // Now there should be at least one entry visible
    let entries = engine
        .list_entries(
            None,
            Page {
                offset: 0,
                limit: 100,
            },
        )
        .expect("list");
    assert!(!entries.is_empty(), "ingest produced no entries");
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_list_entries_via_ffi() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    seed_kdbx(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    engine
        .ingest_from_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("ingest");
    let entries = engine
        .list_entries(
            None,
            Page {
                offset: 0,
                limit: 100,
            },
        )
        .expect("list");
    let acme = entries
        .iter()
        .find(|e| e.title == "acme")
        .expect("acme entry");
    assert_eq!(acme.username, "alice");
    assert_eq!(acme.url, "https://example.com/");
    // UUID round-trips as a canonical string
    let _ = uuid::Uuid::parse_str(&acme.uuid).expect("uuid parses");
    // Summary widening: notes + created_at + accessed_at cross the FFI
    // boundary so Keys-Mac's list view can drive sort/section/search
    // narrowing without a per-row `engine.entry()` round-trip.
    // `seed_kdbx` doesn't set notes — the field still exists, just empty.
    assert_eq!(acme.notes, "");
    assert!(
        acme.created_at > 0,
        "created_at populated by ingest (got {})",
        acme.created_at
    );
    assert!(
        acme.accessed_at > 0,
        "accessed_at populated by ingest (got {})",
        acme.accessed_at
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_reveal_password_returns_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    seed_kdbx(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    engine
        .ingest_from_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("ingest");
    let entries = engine
        .list_entries(
            None,
            Page {
                offset: 0,
                limit: 100,
            },
        )
        .expect("list");
    let acme = entries.iter().find(|e| e.title == "acme").unwrap();
    let plaintext = engine.reveal_password(acme.uuid.clone()).expect("reveal");
    assert_eq!(plaintext, "Tr0ub4dor&3");
}

fn make_group_and_entry(engine: &Engine) -> (String, String) {
    let tree = engine.group_tree().expect("tree");
    let root = tree.iter().find(|g| g.parent_uuid.is_none()).expect("root");
    let group_uuid = engine
        .create_group(
            root.uuid.clone(),
            NewGroupFields {
                name: "Test".into(),
                notes: String::new(),
                icon: IconRef::Builtin { index: 0 },
            },
        )
        .expect("create group");
    let entry_uuid = engine
        .create_entry(
            group_uuid.clone(),
            NewEntryFields {
                title: "Title".into(),
                username: "user".into(),
                url: String::new(),
                notes: String::new(),
                password: "p".into(),
                icon: IconRef::Builtin { index: 0 },
                custom_fields: vec![],
                tags: vec![],
            },
        )
        .expect("create entry");
    (group_uuid, entry_uuid)
}

#[test]
fn engine_create_entry_returns_uuid_string() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    seed_kdbx(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    // We need the group_tree to exist — ingest is async, so do it via
    // a small blocking helper. Use the keys-engine path directly via
    // a separate tokio runtime.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        engine
            .ingest_from_kdbx(
                kdbx_path.to_string_lossy().into_owned(),
                KDBX_PASSWORD.to_owned(),
            )
            .await
            .expect("ingest");
    });
    let (_, entry_uuid) = make_group_and_entry(&engine);
    let parsed = uuid::Uuid::parse_str(&entry_uuid).expect("returned uuid parses");
    assert!(!parsed.is_nil());
}

#[derive(Default)]
struct RecordingObserver {
    events: Mutex<Vec<ChangeEvent>>,
}
impl VaultDataChangeObserver for RecordingObserver {
    fn on_event(&self, event: ChangeEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[test]
fn engine_observer_bridge_receives_events() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    seed_kdbx(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        engine
            .ingest_from_kdbx(
                kdbx_path.to_string_lossy().into_owned(),
                KDBX_PASSWORD.to_owned(),
            )
            .await
            .expect("ingest");
    });
    let observer = Arc::new(RecordingObserver::default());
    engine
        .set_observer(observer.clone() as Arc<dyn VaultDataChangeObserver>)
        .expect("set observer");
    let _ = make_group_and_entry(&engine);
    let events = observer.events.lock().unwrap();
    // We should have at least one GroupsAdded and one EntriesAdded
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::GroupsAdded { .. })),
        "expected GroupsAdded in {events:?}",
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChangeEvent::EntriesAdded { .. })),
        "expected EntriesAdded in {events:?}",
    );
}

/// Test FileWatcher bridge — install a foreign watcher, drive a
/// synthetic event through it, and assert it reaches the engine's
/// internal observer (we observe via VaultState transitions).
#[derive(Default)]
struct TestFileWatcher {
    observer: Mutex<Option<Arc<dyn VaultFileWatcherObserver>>>,
}
impl VaultFileWatcher for TestFileWatcher {
    fn set_observer(&self, observer: Option<Arc<dyn VaultFileWatcherObserver>>) {
        *self.observer.lock().unwrap() = observer;
    }
}

#[test]
fn engine_file_watcher_bridge_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let watcher = Arc::new(TestFileWatcher::default());
    let engine = Engine::open(
        db_path.to_string_lossy().into_owned(),
        Arc::new(FixedDbKey),
        Arc::new(FixedProtector),
        Some(watcher.clone() as Arc<dyn VaultFileWatcher>),
    )
    .expect("open");
    // The engine installs its internal observer on open via the
    // bridge — verify by firing an `Unavailable` event and watching
    // VaultState transition.
    let obs = watcher.observer.lock().unwrap().clone();
    let obs = obs.expect("engine installed observer through bridge");
    obs.on_event(FileWatcherEvent::Unavailable {
        reason: "test-disconnect".into(),
    });
    let state = engine.state().expect("state");
    assert!(
        matches!(
            state,
            keys_ffi::VaultState::DisconnectedFileUnreadable { .. }
        ),
        "got {state:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_async_save_completes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    seed_kdbx(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    engine
        .ingest_from_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("ingest");
    engine
        .save_to_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("save");
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_async_reconcile_completes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    seed_kdbx(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    engine
        .ingest_from_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("ingest");
    // First save so common-ancestor is set
    engine
        .save_to_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("save");
    // Reconcile with unchanged disk → NoChange or Merged
    let result = engine
        .reconcile_with_disk(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("reconcile");
    // NoChange or Merged (a save_to_kdbx writes the projection, which
    // is structurally identical to local).
    assert!(
        matches!(
            result,
            keys_ffi::MergeResult::NoChange | keys_ffi::MergeResult::Merged { .. }
        ),
        "got {result:?}",
    );
}

#[test]
fn engine_predicate_serialisation_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let engine = open_fresh_engine(&db_path);
    // Build a non-trivial predicate via the FFI mirror.
    let pred = Predicate::And {
        predicates: vec![
            Predicate::TagEquals {
                tag: "banking".into(),
            },
            Predicate::Not {
                predicates: vec![Predicate::Expired],
            },
            Predicate::ModifiedWithin {
                duration_secs: 86_400 * 7,
            },
        ],
    };
    let id = engine
        .create_smart_folder("Test Folder".into(), pred.clone())
        .expect("create folder");
    let fetched = engine.smart_folder(id).expect("fetch").expect("some");
    assert_eq!(fetched.name, "Test Folder");
    assert!(fetched.evaluable);
    // Round-trip check: shape of the decoded mirror should match what
    // we pushed (And with 3 children).
    match fetched.predicate {
        Predicate::And { predicates } => assert_eq!(predicates.len(), 3),
        other => panic!("expected And, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_conflict_resolution_apply_not_found() {
    // No real conflict in this lightweight test — exercise the FFI
    // path to apply_conflict_resolution with an unknown id and confirm
    // it surfaces NotFound (rather than panicking through the
    // ResolutionFfi → KmResolution conversion).
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let engine = open_fresh_engine(&db_path);
    let err = engine
        .apply_conflict_resolution(
            9999,
            keys_ffi::ResolutionFfi::new(vec![], vec![], vec![], vec![]),
        )
        .await
        .expect_err("must fail");
    assert!(
        matches!(err, EngineError::NotFound { ref entity } if entity == "conflict_payload"),
        "got {err:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn engine_pending_conflict_peek_then_apply() {
    use keepass_core::CompositeKey;
    use keepass_core::kdbx::Kdbx;
    use keepass_core::model::{EntryId, HistoryPolicy};
    use keys_ffi::{
        ConflictSideFfi, DeleteEditChoiceEntryFfi, EngineEntryUpdate, EntryAttachmentChoiceFfi,
        EntryFieldChoiceFfi, EntryIconChoiceFfi, FieldChoiceFfi, MergeResult, ResolutionFfi,
    };

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    seed_kdbx(&kdbx_path);
    let engine = open_fresh_engine(&db_path);

    // Ingest + first save to set the common ancestor.
    engine
        .ingest_from_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("ingest");
    engine
        .save_to_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("save");

    // Grab the seed entry's uuid via the projection.
    let summaries = engine
        .list_entries(
            None,
            Page {
                offset: 0,
                limit: 100,
            },
        )
        .expect("entries");
    let target = summaries
        .iter()
        .find(|e| e.title == "acme")
        .expect("seed entry present")
        .clone();

    // Local edit: change the title.
    engine
        .update_entry(
            target.uuid.clone(),
            EngineEntryUpdate {
                title: Some("local-title".into()),
                ..Default::default()
            },
        )
        .expect("local update");

    // Disk edit: open the kdbx independently and change the same entry's title.
    let composite = CompositeKey::from_password(KDBX_PASSWORD.as_bytes());
    let mut disk_kdbx = Kdbx::open(&kdbx_path)
        .expect("open kdbx")
        .read_header()
        .expect("header")
        .unlock(&composite)
        .expect("unlock");
    let uuid = uuid::Uuid::parse_str(&target.uuid).expect("parse uuid");
    disk_kdbx
        .edit_entry(EntryId(uuid), HistoryPolicy::Snapshot, |e| {
            e.set_title("disk-title");
        })
        .expect("disk edit");
    let bytes = disk_kdbx.save_to_bytes().expect("save bytes");
    std::fs::write(&kdbx_path, &bytes).expect("write");

    // Reconcile — expect a conflict.
    let result = engine
        .reconcile_with_disk(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("reconcile");
    let conflict_id = match result {
        MergeResult::Conflict { id } => id,
        other => panic!("expected Conflict, got {other:?}"),
    };

    // FFI peek — twice, same shape.
    let first = engine
        .pending_conflict(conflict_id)
        .expect("peek ok")
        .expect("payload present");
    assert_eq!(first.id, conflict_id);
    assert_eq!(first.entry_conflicts.len(), 1, "single entry in conflict");
    let entry_conflict = &first.entry_conflicts[0];
    assert_eq!(entry_conflict.entry_uuid, target.uuid);
    assert_eq!(entry_conflict.local.title, "local-title");
    assert_eq!(entry_conflict.remote.title, "disk-title");
    assert!(
        entry_conflict.field_deltas.iter().any(|d| d.key == "Title"),
        "Title delta present in {:?}",
        entry_conflict.field_deltas,
    );

    let second = engine
        .pending_conflict(conflict_id)
        .expect("peek again ok")
        .expect("payload still present");
    assert_eq!(
        second.entry_conflicts.len(),
        first.entry_conflicts.len(),
        "peek is idempotent",
    );

    // Build a resolution: take remote on Title.
    let resolution = ResolutionFfi::new(
        vec![EntryFieldChoiceFfi::new(
            target.uuid.clone(),
            vec![FieldChoiceFfi::new("Title", ConflictSideFfi::Remote)],
        )],
        Vec::<EntryAttachmentChoiceFfi>::new(),
        Vec::<EntryIconChoiceFfi>::new(),
        Vec::<DeleteEditChoiceEntryFfi>::new(),
    );

    engine
        .apply_conflict_resolution(conflict_id, resolution)
        .await
        .expect("apply");

    // Peek now returns None.
    assert!(
        engine
            .pending_conflict(conflict_id)
            .expect("peek ok")
            .is_none(),
        "peek returns None once apply has consumed the stash",
    );

    // And the entry's title flipped to the remote side.
    let after = engine.entry(target.uuid).expect("entry").expect("present");
    assert_eq!(after.title, "disk-title");
}

#[test]
fn engine_pending_conflict_unknown_id_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let engine = open_fresh_engine(&db_path);
    let res = engine.pending_conflict(424_242).expect("call ok");
    assert!(res.is_none(), "unknown id returns None");
}

/// Seed a fresh KDBX with one entry that owns an attachment and one
/// snapshotted history revision. Returns the entry's UUID string, the
/// kdbx path, and the attachment bytes the test should expect.
fn seed_kdbx_with_attachment_and_history(kdbx_path: &std::path::Path) -> (String, Vec<u8>) {
    use keepass_core::CompositeKey;
    use keepass_core::kdbx::Kdbx;
    use keepass_core::model::{HistoryPolicy, NewEntry};
    use secrecy::SecretString;
    let composite = CompositeKey::from_password(KDBX_PASSWORD.as_bytes());
    let mut kdbx = Kdbx::create_empty_v4(&composite, "test").expect("create");
    let root = kdbx.vault().root.id;
    let attachment_bytes = b"hello-attachment-payload".to_vec();
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("v0")
                .username("alice-v0")
                .url("https://v0.example/login")
                .password(SecretString::from("initial-password-A!")),
        )
        .expect("add");
    // Seed metadata + attachment on v0 (no snapshot).
    {
        let bytes = attachment_bytes.clone();
        kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, move |e| {
            e.set_notes("v0 notes");
            e.set_tags(vec!["alpha".into()]);
            e.set_icon_id(11);
            e.attach("doc.txt", bytes, false);
        })
        .expect("seed v0");
    }
    // Snapshot the v0 state into history, then mutate to v1.
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("v1");
        e.set_notes("v1 notes");
        e.set_tags(vec!["beta".into(), "gamma".into()]);
        e.set_icon_id(2);
        e.set_password(SecretString::from("rotated-password-B!"));
    })
    .expect("edit v1");
    let bytes_out = kdbx.save_to_bytes().expect("save bytes");
    std::fs::write(kdbx_path, bytes_out).expect("write");
    (id.0.to_string(), attachment_bytes)
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_attachment_bytes_via_ffi() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let (uuid, expected_bytes) = seed_kdbx_with_attachment_and_history(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    engine
        .ingest_from_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("ingest");

    let read = engine
        .attachment_bytes(uuid.clone(), "doc.txt".to_owned())
        .expect("attachment_bytes via FFI");
    assert_eq!(read, expected_bytes);

    // NotFound for missing attachment name.
    let err = engine
        .attachment_bytes(uuid, "missing.bin".to_owned())
        .expect_err("missing attachment should NotFound");
    matches!(err, EngineError::NotFound { ref entity } if entity == "attachment")
        .then_some(())
        .expect("NotFound attachment");
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_history_attachment_bytes_via_ffi() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let (uuid, expected_bytes) = seed_kdbx_with_attachment_and_history(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    engine
        .ingest_from_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("ingest");

    // Happy path — the v0 snapshot recorded the attachment, so the
    // history-bytes lookup must return the same bytes the live entry
    // surfaced before the rename.
    let read = engine
        .history_attachment_bytes(uuid.clone(), 0, "doc.txt".to_owned())
        .expect("history_attachment_bytes via FFI");
    assert_eq!(read, expected_bytes);

    // NotFound for a name that's not in this snapshot.
    let err = engine
        .history_attachment_bytes(uuid.clone(), 0, "missing.bin".to_owned())
        .expect_err("missing attachment name should NotFound");
    matches!(err, EngineError::NotFound { ref entity } if entity == "attachment")
        .then_some(())
        .expect("NotFound attachment for missing name");

    // NotFound for a history index that doesn't exist.
    let err = engine
        .history_attachment_bytes(uuid, 99, "doc.txt".to_owned())
        .expect_err("missing history index should NotFound");
    matches!(err, EngineError::NotFound { ref entity } if entity == "attachment")
        .then_some(())
        .expect("NotFound attachment for missing history index");
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_history_widening_round_trip_via_ffi() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let (uuid, _expected_bytes) = seed_kdbx_with_attachment_and_history(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    engine
        .ingest_from_kdbx(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
        )
        .await
        .expect("ingest");

    let history = engine.history(uuid).expect("history via FFI");
    assert_eq!(history.len(), 1, "one snapshot expected");
    let snap = &history[0];

    // Confirm the new widened fields populate at the FFI boundary.
    assert_eq!(snap.title, "v0");
    assert_eq!(snap.username, "alice-v0");
    assert_eq!(snap.url, "https://v0.example/login");
    assert_eq!(snap.url_host, "v0.example");
    assert_eq!(snap.notes, "v0 notes");
    assert_eq!(snap.tags, vec!["alpha".to_string()]);
    match snap.icon {
        IconRef::Builtin { index: 11 } => {}
        ref other => panic!("expected Builtin {{ index: 11 }}, got {other:?}"),
    }
    assert!(
        snap.password_strength_bucket.is_some(),
        "snapshot password is non-empty → strength bucket must surface"
    );
    assert!(
        snap.password_entropy.unwrap_or(0.0) > 0.0,
        "expected positive entropy on snapshot password"
    );
    assert!(
        snap.attachments.iter().any(|a| a.name == "doc.txt"),
        "snapshot should record the attachment metadata: {snap:?}"
    );
    assert!(snap.created_at > 0);
    assert!(snap.modified_at > 0);
}

// ─────────────────────── custom-icon FFI surface ───────────────────────

#[test]
fn engine_custom_icon_surface_round_trips_via_ffi() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    seed_kdbx(&kdbx_path);
    let engine = open_fresh_engine(&db_path);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        engine
            .ingest_from_kdbx(
                kdbx_path.to_string_lossy().into_owned(),
                KDBX_PASSWORD.to_owned(),
            )
            .await
            .expect("ingest");
    });

    let icon_bytes = b"\x89PNG\r\n\x1a\nffi-custom-icon-payload".to_vec();

    // add_custom_icon returns a UUID string; dedup returns the same.
    let uuid_a = engine
        .add_custom_icon(icon_bytes.clone())
        .expect("add icon");
    let uuid_dup = engine
        .add_custom_icon(icon_bytes.clone())
        .expect("dedup add");
    assert_eq!(uuid_a, uuid_dup, "dedup-by-hash must return same UUID");

    // custom_icon_bytes round-trips the blob.
    let fetched = engine
        .custom_icon_bytes(uuid_a.clone())
        .expect("fetch bytes")
        .expect("some");
    assert_eq!(fetched, icon_bytes);

    // custom_icon_bytes returns None for an unknown UUID.
    let unknown = uuid::Uuid::new_v4().to_string();
    assert!(
        engine
            .custom_icon_bytes(unknown)
            .expect("fetch unknown")
            .is_none()
    );

    // clear_entry_custom_icon: create an entry pointing at the icon,
    // clear, confirm the row's `icon` reverts to a built-in ref while
    // the pool blob survives.
    let (_g, entry_uuid) = make_group_and_entry(&engine);
    // Wire the icon onto the entry via update_entry's icon patch.
    engine
        .update_entry(
            entry_uuid.clone(),
            keys_ffi::EngineEntryUpdate {
                title: None,
                username: None,
                url: None,
                notes: None,
                password: None,
                icon: Some(IconRef::Custom {
                    uuid: uuid_a.clone(),
                }),
                expires_at: None,
            },
        )
        .expect("attach icon");

    engine
        .clear_entry_custom_icon(entry_uuid.clone())
        .expect("clear");

    let entry = engine
        .entry(entry_uuid.clone())
        .expect("entry")
        .expect("some");
    assert!(
        matches!(entry.icon, IconRef::Builtin { .. }),
        "entry icon should revert to Builtin after clear, got {:?}",
        entry.icon
    );

    // Blob still in the pool — no GC on clear.
    let still_there = engine
        .custom_icon_bytes(uuid_a)
        .expect("refetch")
        .expect("blob retained");
    assert_eq!(still_there, icon_bytes);
}
