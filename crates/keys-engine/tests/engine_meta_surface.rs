//! Tests for the Phase 6.17-B meta-surface engine APIs.
//!
//! Six methods land here: `recycle_bin_uuid`, `recycle_bin_enabled`,
//! `history_max_items`, `history_max_size`, plus setters for the two
//! history caps. They back the Keys-Mac downstream slice that retires
//! the in-memory `Vault` meta shim.

use std::path::Path;
use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{Group, GroupId};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{ChangeEvent, DataChangeObserver, DbKey, Engine, KeyProvider, KeyProviderError};
use rusqlite::Connection;
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
const COMPOSITE_PW: &[u8] = b"engine-meta-surface-tests";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(COMPOSITE_PW)
}

fn fresh_kdbx(name: &str) -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), name, Some(protector())).expect("create")
}

fn db_key_hex() -> String {
    let mut s = String::with_capacity(64);
    for b in &DB_KEY_BYTES {
        use std::fmt::Write as _;
        write!(&mut s, "{b:02x}").expect("hex");
    }
    s
}

fn raw_open(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("raw open");
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\"", db_key_hex()))
        .expect("apply key");
    conn
}

fn open_engine(path: &Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("engine open")
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

// ─────────────────────── recycle_bin_uuid ───────────────────────

#[test]
fn recycle_bin_uuid_is_none_when_no_bin_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("no-bin");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert_eq!(engine.recycle_bin_uuid().expect("read"), None);
}

#[test]
fn recycle_bin_uuid_returns_bin_group_uuid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");

    // Build a kdbx with a bin group and point Meta at it.
    let mut kdbx = fresh_kdbx("with-bin");
    let bin_id = GroupId(Uuid::new_v4());
    let mut bin = Group::empty(bin_id);
    bin.name = "Recycle Bin".into();
    let mut vault = kdbx.vault().clone();
    vault.root.groups.push(bin);
    vault.meta.recycle_bin_uuid = Some(bin_id);
    vault.meta.recycle_bin_enabled = true;
    kdbx.replace_vault(vault);

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let got = engine.recycle_bin_uuid().expect("read");
    assert_eq!(got, Some(bin_id.0.to_string()));
}

// ─────────────────────── recycle_bin_enabled ───────────────────────

#[test]
fn recycle_bin_enabled_reads_setting_row_true() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("enabled-true");
    let mut vault = kdbx.vault().clone();
    vault.meta.recycle_bin_enabled = true;
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert!(engine.recycle_bin_enabled().expect("read"));
}

#[test]
fn recycle_bin_enabled_reads_setting_row_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("enabled-false");
    let mut vault = kdbx.vault().clone();
    vault.meta.recycle_bin_enabled = false;
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert!(!engine.recycle_bin_enabled().expect("read"));
}

#[test]
fn recycle_bin_enabled_falls_back_when_setting_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("legacy-no-setting");
    {
        let mut engine = open_engine(&path);
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        engine.close().expect("close");
    }
    // Delete the setting row to simulate a pre-fix legacy DB.
    let conn = raw_open(&path);
    conn.execute(
        "DELETE FROM setting WHERE key = 'meta.recycle_bin_enabled'",
        [],
    )
    .expect("delete");
    drop(conn);

    let engine = open_engine(&path);
    // No bin group exists -> fallback says false.
    assert!(!engine.recycle_bin_enabled().expect("read"));
}

// ─────────────────────── history_max_items / size getters ───────────────────────

#[test]
fn history_max_items_reads_persisted_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("hmi");
    let mut vault = kdbx.vault().clone();
    vault.meta.history_max_items = 42;
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert_eq!(engine.history_max_items().expect("read"), 42);
}

#[test]
fn history_max_size_reads_persisted_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let mut kdbx = fresh_kdbx("hms");
    let mut vault = kdbx.vault().clone();
    vault.meta.history_max_size = 12_345_678;
    kdbx.replace_vault(vault);
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    assert_eq!(engine.history_max_size().expect("read"), 12_345_678);
}

// ─────────────────────── setters ───────────────────────

#[test]
fn set_history_max_items_persists_and_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("set-hmi");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    engine.set_history_max_items(7).expect("set");
    assert_eq!(engine.history_max_items().expect("read"), 7);

    // Survives a close-and-reopen.
    engine.close().expect("close");
    let engine = open_engine(&path);
    assert_eq!(engine.history_max_items().expect("reread"), 7);
}

#[test]
fn set_history_max_size_persists_and_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("set-hms");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    engine.set_history_max_size(999_999).expect("set");
    assert_eq!(engine.history_max_size().expect("read"), 999_999);

    engine.close().expect("close");
    let engine = open_engine(&path);
    assert_eq!(engine.history_max_size().expect("reread"), 999_999);
}

#[test]
fn set_history_max_items_emits_meta_updated_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("emit-hmi");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());
    engine.set_history_max_items(15).expect("set");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::MetaUpdated { keys } => {
            assert_eq!(keys, &vec!["meta.history_max_items".to_string()]);
        }
        other => panic!("expected MetaUpdated, got {other:?}"),
    }
}

#[test]
fn set_history_max_size_emits_meta_updated_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("emit-hms");
    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());
    engine.set_history_max_size(2 * 1024 * 1024).expect("set");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::MetaUpdated { keys } => {
            assert_eq!(keys, &vec!["meta.history_max_size".to_string()]);
        }
        other => panic!("expected MetaUpdated, got {other:?}"),
    }
}
