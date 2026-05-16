//! Integration tests for [`Engine::history`] (task 3.1 completion).
//!
//! Companion to `history_wrap.rs` (which covers reveal of protected
//! history fields). This file focuses on the structural-list surface:
//! ordering, empty-history behaviour, missing-entry errors, and the
//! invariant that protected plaintext never appears in the
//! [`HistoricEntry`] payload.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{CustomFieldValue, HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, EngineError, KeyProvider, KeyProviderError};
use secrecy::SecretString;
use uuid::Uuid;

// ── test wiring (same shape as tests/history_wrap.rs) ──────────────────

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

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn history_returns_empty_for_entry_without_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(root, NewEntry::new("solo"))
        .expect("add entry");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let history = engine.history(id.0).expect("history");
    assert!(
        history.is_empty(),
        "expected empty history, got {history:?}"
    );
}

#[test]
fn history_returns_snapshots_in_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("v0")
                .username("user-v0")
                .url("https://v0.example"),
        )
        .expect("add");

    // Three snapshotting edits — each one freezes the previous state
    // as a history snapshot and applies the new state to the live row.
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("v1");
        e.set_username("user-v1");
        e.set_url("https://v1.example");
    })
    .expect("edit v1");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("v2");
        e.set_username("user-v2");
        e.set_url("https://v2.example");
    })
    .expect("edit v2");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("v3");
        e.set_username("user-v3");
        e.set_url("https://v3.example");
    })
    .expect("edit v3");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let history = engine.history(id.0).expect("history");
    assert_eq!(history.len(), 3);

    // Oldest-first, with monotonically increasing history_index.
    assert_eq!(history[0].history_index, 0);
    assert_eq!(history[1].history_index, 1);
    assert_eq!(history[2].history_index, 2);

    assert_eq!(history[0].title, "v0");
    assert_eq!(history[0].username, "user-v0");
    assert_eq!(history[0].url, "https://v0.example");

    assert_eq!(history[1].title, "v1");
    assert_eq!(history[2].title, "v2");
}

#[test]
fn history_does_not_include_protected_plaintext() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("api").password(SecretString::from("ancient-secret")),
        )
        .expect("add");
    // Seed a protected custom field on the live entry…
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("ancient-token")),
        );
    })
    .expect("set token");
    // …then rotate, snapshotting the prior state into history.
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("modern-secret"));
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("modern-token")),
        );
    })
    .expect("rotate");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let history = engine.history(id.0).expect("history");
    assert_eq!(history.len(), 1, "one history snapshot expected");

    let snap = &history[0];
    assert!(
        snap.custom_field_names.contains(&"Token".to_string()),
        "Token name should surface in custom_field_names: {snap:?}"
    );

    // The `HistoricEntry` payload deliberately doesn't carry field
    // values; only the names. Belt-and-braces: serialise the whole
    // struct and confirm no plaintext leaked anywhere.
    let json = serde_json::to_string(&snap).expect("serialise");
    assert!(
        !json.contains("ancient-secret"),
        "password plaintext leaked into HistoricEntry: {json}"
    );
    assert!(
        !json.contains("ancient-token"),
        "protected custom field plaintext leaked into HistoricEntry: {json}"
    );
}

#[test]
fn history_returns_not_found_for_missing_uuid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let err = engine
        .history(Uuid::new_v4())
        .expect_err("missing uuid should be NotFound");
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, "entry"),
        other => panic!("expected NotFound {{ entity: \"entry\" }}, got {other:?}"),
    }
}
