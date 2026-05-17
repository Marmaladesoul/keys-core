//! Tests for the Phase 6.17-E touch / clear-last-access engine APIs.
//!
//! Two engine methods land here: `touch_entry` (read-touch flow used
//! by `AutoFill` and in-app reveal — bumps `last_used_at` without
//! touching `modified_at`) and `clear_entry_last_access` (user-driven
//! reset of the last-access stamp). They back the Keys-Mac downstream
//! slice that retires the legacy in-memory `Vault::touch_entry` /
//! `Vault::clear_entry_last_access` shims.

use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    ChangeEvent, DataChangeObserver, DbKey, Engine, IconRef, KeyProvider, KeyProviderError,
    NewEntryFields,
};
use secrecy::SecretString;
use uuid::Uuid;

// ─────────────────────── infrastructure ───────────────────────

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
const COMPOSITE_PW: &[u8] = b"engine-touch-entry-tests";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(COMPOSITE_PW)
}

fn fresh_kdbx(name: &str) -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), name, Some(protector())).expect("create")
}

fn engine_with_one_entry() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("touch-entry");
    let root_uuid = kdbx.vault().root.id.0;
    let mut engine =
        Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("engine open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    let entry_uuid = engine
        .create_entry(
            root_uuid,
            NewEntryFields {
                title: "to-touch".into(),
                username: String::new(),
                url: String::new(),
                notes: String::new(),
                password: SecretString::from("pw"),
                icon: IconRef::Builtin(0),
                custom_fields: Vec::new(),
                tags: Vec::new(),
            },
        )
        .expect("create");
    (engine, entry_uuid, dir)
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

// ─────────────────────── touch_entry ───────────────────────

#[test]
fn touch_entry_sets_last_used_at_and_leaves_modified_at_alone() {
    let (mut engine, entry_uuid, _dir) = engine_with_one_entry();

    let before = engine.entry(entry_uuid).expect("read").expect("some");
    assert!(
        before.last_used_at.is_none(),
        "new entry should have a null last_used_at"
    );
    let modified_before = before.modified_at;

    // Sleep just enough to make the millisecond clock visibly tick
    // — `last_used_at` after the touch must be strictly greater than
    // `modified_at` at create time.
    std::thread::sleep(std::time::Duration::from_millis(5));

    engine.touch_entry(entry_uuid).expect("touch");

    let after = engine.entry(entry_uuid).expect("read").expect("some");
    let last_used = after.last_used_at.expect("touch should set last_used_at");
    assert!(
        last_used >= modified_before,
        "last_used_at ({last_used}) should be >= the pre-touch modified_at ({modified_before})"
    );
    assert_eq!(
        after.modified_at, modified_before,
        "touch must not bump modified_at"
    );
}

#[test]
fn touch_entry_emits_entry_touched_event() {
    let (mut engine, entry_uuid, _dir) = engine_with_one_entry();

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());

    engine.touch_entry(entry_uuid).expect("touch");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::EntryTouched { uuid } => assert_eq!(*uuid, entry_uuid),
        other => panic!("expected EntryTouched, got {other:?}"),
    }
}

#[test]
fn touch_entry_unknown_returns_not_found() {
    let (mut engine, _entry, _dir) = engine_with_one_entry();
    let err = engine.touch_entry(Uuid::new_v4()).expect_err("should fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("entry"),
        "expected NotFound for entry, got {msg}"
    );
}

// ─────────────────────── clear_entry_last_access ───────────────────────

#[test]
fn clear_entry_last_access_nulls_last_used_at() {
    let (mut engine, entry_uuid, _dir) = engine_with_one_entry();

    engine.touch_entry(entry_uuid).expect("touch");
    let touched = engine.entry(entry_uuid).expect("read").expect("some");
    assert!(touched.last_used_at.is_some(), "touch should populate it");
    let modified_after_touch = touched.modified_at;

    engine
        .clear_entry_last_access(entry_uuid)
        .expect("clear last access");

    let cleared = engine.entry(entry_uuid).expect("read").expect("some");
    assert_eq!(
        cleared.last_used_at, None,
        "clear should null out last_used_at"
    );
    assert_eq!(
        cleared.modified_at, modified_after_touch,
        "clear must not bump modified_at"
    );
}

#[test]
fn clear_entry_last_access_emits_entries_updated() {
    let (mut engine, entry_uuid, _dir) = engine_with_one_entry();
    engine.touch_entry(entry_uuid).expect("touch");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());

    engine
        .clear_entry_last_access(entry_uuid)
        .expect("clear last access");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::EntriesUpdated(uuids) => assert_eq!(uuids, &vec![entry_uuid]),
        other => panic!("expected EntriesUpdated, got {other:?}"),
    }
}

#[test]
fn clear_entry_last_access_unknown_returns_not_found() {
    let (mut engine, _entry, _dir) = engine_with_one_entry();
    let err = engine
        .clear_entry_last_access(Uuid::new_v4())
        .expect_err("should fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("entry"),
        "expected NotFound for entry, got {msg}"
    );
}
