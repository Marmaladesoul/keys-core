//! Tests for the Phase 6.17-D custom-icon engine APIs.
//!
//! Three engine methods land here: `add_custom_icon` (SHA-256 dedup),
//! `clear_entry_custom_icon` (entry-side reference clear, leaves the
//! pool blob in place), and `custom_icon_bytes` (raw blob fetch by
//! UUID). They back the Keys-Mac downstream slice that retires the
//! in-memory `Vault::add_custom_icon` / `custom_icon_image` shim.

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
const COMPOSITE_PW: &[u8] = b"engine-custom-icon-surface-tests";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(COMPOSITE_PW)
}

fn fresh_kdbx(name: &str) -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), name, Some(protector())).expect("create")
}

fn engine_with_empty_vault() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("engine.sqlite");
    let kdbx = fresh_kdbx("custom-icon");
    let root_uuid = kdbx.vault().root.id.0;
    let mut engine =
        Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("engine open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, root_uuid, dir)
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

/// A few bytes of synthetic PNG-ish data. The engine doesn't decode
/// the blob — KDBX treats it as opaque — so the exact bytes don't
/// matter as long as the tests use distinct payloads where dedup
/// behaviour is under test.
const ICON_A: &[u8] = b"\x89PNG\r\n\x1a\nfake-icon-a-payload";
const ICON_B: &[u8] = b"\x89PNG\r\n\x1a\nfake-icon-b-different";

fn new_entry_with_icon(title: &str, icon: IconRef) -> NewEntryFields {
    NewEntryFields {
        title: title.into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("pw"),
        icon,
        custom_fields: Vec::new(),
        tags: Vec::new(),
    }
}

// ─────────────────────── add_custom_icon ───────────────────────

#[test]
fn add_custom_icon_round_trips_bytes() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let uuid_str = engine.add_custom_icon(ICON_A).expect("add");
    let uuid = Uuid::parse_str(&uuid_str).expect("parse");

    let bytes = engine
        .custom_icon_bytes(uuid)
        .expect("fetch")
        .expect("some");
    assert_eq!(bytes, ICON_A);
}

#[test]
fn add_custom_icon_dedups_same_bytes_to_same_uuid() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let first = engine.add_custom_icon(ICON_A).expect("first add");
    let second = engine.add_custom_icon(ICON_A).expect("second add");
    assert_eq!(
        first, second,
        "second add with identical bytes should return the existing UUID"
    );
}

#[test]
fn add_custom_icon_distinguishes_distinct_bytes() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let a = engine.add_custom_icon(ICON_A).expect("add a");
    let b = engine.add_custom_icon(ICON_B).expect("add b");
    assert_ne!(a, b, "distinct payloads must produce distinct UUIDs");
}

#[test]
fn add_custom_icon_emits_meta_updated_on_fresh_insert() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());

    engine.add_custom_icon(ICON_A).expect("add");

    let events = observer.snapshot();
    assert_eq!(
        events.len(),
        1,
        "fresh insert should emit exactly one event"
    );
    match &events[0] {
        ChangeEvent::MetaUpdated { keys } => {
            assert_eq!(keys, &vec!["meta.custom_icons".to_string()]);
        }
        other => panic!("expected MetaUpdated, got {other:?}"),
    }
}

#[test]
fn add_custom_icon_does_not_emit_on_dedup_hit() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    // Prime the pool before the observer attaches.
    engine.add_custom_icon(ICON_A).expect("prime");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());

    // Same bytes → dedup hit → no event.
    let _ = engine.add_custom_icon(ICON_A).expect("dedup add");
    assert!(
        observer.snapshot().is_empty(),
        "dedup hit must not emit MetaUpdated (pool unchanged)"
    );
}

// ─────────────────────── custom_icon_bytes ───────────────────────

#[test]
fn custom_icon_bytes_returns_none_for_unknown_uuid() {
    let (engine, _root, _dir) = engine_with_empty_vault();
    let unknown = Uuid::new_v4();
    assert_eq!(engine.custom_icon_bytes(unknown).expect("fetch"), None);
}

// ─────────────────────── clear_entry_custom_icon ───────────────────────

#[test]
fn clear_entry_custom_icon_nulls_ref_but_leaves_blob_in_pool() {
    let (mut engine, root, _dir) = engine_with_empty_vault();

    let icon_uuid_str = engine.add_custom_icon(ICON_A).expect("add icon");
    let icon_uuid = Uuid::parse_str(&icon_uuid_str).expect("parse");
    let entry_uuid = engine
        .create_entry(
            root,
            new_entry_with_icon("with-icon", IconRef::Custom(icon_uuid)),
        )
        .expect("create");

    // Sanity: entry references the icon as a custom ref.
    let entry = engine.entry(entry_uuid).expect("entry").expect("some");
    assert!(
        matches!(entry.icon, IconRef::Custom(u) if u == icon_uuid),
        "expected Custom({icon_uuid}) icon ref, got {:?}",
        entry.icon
    );

    engine
        .clear_entry_custom_icon(entry_uuid)
        .expect("clear icon");

    // Reference cleared: row falls back to the built-in icon slot
    // (icon_index is left untouched; default is 0).
    let entry_after = engine.entry(entry_uuid).expect("entry").expect("some");
    assert!(
        matches!(entry_after.icon, IconRef::Builtin(_)),
        "icon should fall back to built-in after clear, got {:?}",
        entry_after.icon
    );

    // Blob still in pool — no GC on clear.
    let bytes = engine
        .custom_icon_bytes(icon_uuid)
        .expect("fetch")
        .expect("blob still present");
    assert_eq!(bytes, ICON_A);
}

#[test]
fn link_entry_custom_icon_sets_icon_without_history_or_mtime_bump() {
    // A fetched favicon is cosmetic enrichment, not a user edit: it
    // must not archive a <History> snapshot or bump modified_at.
    let (mut engine, root, _dir) = engine_with_empty_vault();

    let entry_uuid = engine
        .create_entry(
            root,
            new_entry_with_icon("favicon-target", IconRef::Builtin(0)),
        )
        .expect("create");
    let before = engine.entry(entry_uuid).expect("entry").expect("some");
    assert_eq!(before.history_count, 0, "fresh entry has no history");

    let icon_uuid_str = engine.add_custom_icon(ICON_A).expect("add icon");
    let icon_uuid = Uuid::parse_str(&icon_uuid_str).expect("parse");

    engine
        .link_entry_custom_icon(entry_uuid, icon_uuid)
        .expect("link favicon");

    let after = engine.entry(entry_uuid).expect("entry").expect("some");
    assert!(
        matches!(after.icon, IconRef::Custom(u) if u == icon_uuid),
        "favicon should be linked as the custom icon, got {:?}",
        after.icon
    );
    assert_eq!(
        after.history_count, 0,
        "a favicon link must NOT archive a history snapshot",
    );
    assert_eq!(
        after.modified_at, before.modified_at,
        "a favicon link must NOT bump modified_at",
    );
}

#[test]
fn clear_entry_custom_icon_emits_entries_updated() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let icon_uuid_str = engine.add_custom_icon(ICON_A).expect("add icon");
    let icon_uuid = Uuid::parse_str(&icon_uuid_str).expect("parse");
    let entry_uuid = engine
        .create_entry(
            root,
            new_entry_with_icon("with-icon", IconRef::Custom(icon_uuid)),
        )
        .expect("create");

    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());

    engine
        .clear_entry_custom_icon(entry_uuid)
        .expect("clear icon");

    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    match &events[0] {
        ChangeEvent::EntriesUpdated(uuids) => {
            assert_eq!(uuids, &vec![entry_uuid]);
        }
        other => panic!("expected EntriesUpdated, got {other:?}"),
    }
}

#[test]
fn clear_entry_custom_icon_unknown_entry_returns_not_found() {
    let (mut engine, _root, _dir) = engine_with_empty_vault();
    let err = engine
        .clear_entry_custom_icon(Uuid::new_v4())
        .expect_err("should fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("entry"),
        "expected NotFound for entry, got {msg}"
    );
}
