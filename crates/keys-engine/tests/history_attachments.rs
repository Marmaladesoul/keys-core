//! Integration tests for [`Engine::history_attachment_bytes`].
//!
//! Resolves a named attachment as it existed in a specific history
//! snapshot of an entry through the snapshot JSON's recorded SHA-256 →
//! `attachment_blob` chain. Covers happy-path retrieval and the four
//! `NotFound` paths: attachment name missing in the snapshot, history
//! index missing, entry missing, and the empty-`sha256_hex` case (which
//! would surface for any pre-widening `snapshot_json` row).

use std::fmt::Write as _;
use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, EngineError, KeyProvider, KeyProviderError};
use uuid::Uuid;

// ── test wiring ────────────────────────────────────────────────────────

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

const SESSION_KEY_BYTES: [u8; 32] = [0x4d; 32];
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

fn expect_not_found(err: EngineError, expected_entity: &str) {
    match err {
        EngineError::NotFound { entity } => assert_eq!(entity, expected_entity),
        other => panic!("expected NotFound {{ entity: \"{expected_entity}\" }}, got {other:?}"),
    }
}

// ── tests ──────────────────────────────────────────────────────────────

#[test]
fn history_attachment_bytes_returns_blob() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("logo")).expect("add");
    let bytes = b"\x89PNG\r\n\x1a\n-snapshot-payload".to_vec();
    // Seed the attachment on v0 without snapshotting.
    {
        let b = bytes.clone();
        kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, move |e| {
            e.attach("logo.png", b, false);
        })
        .expect("attach v0");
    }
    // Snapshot v0 into history, then mutate the live entry. The
    // snapshot must carry the attachment ref so history_attachment_bytes
    // can resolve it.
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("v1");
    })
    .expect("edit v1");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let read = engine
        .history_attachment_bytes(id.0, 0, "logo.png")
        .expect("history_attachment_bytes");
    assert_eq!(read, bytes);
}

#[test]
fn history_attachment_bytes_returns_not_found_for_missing_attachment_in_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("e")).expect("add");
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("present.bin", b"data".to_vec(), false);
    })
    .expect("attach");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("v1");
    })
    .expect("snapshot");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let err = engine
        .history_attachment_bytes(id.0, 0, "absent.bin")
        .expect_err("missing name should NotFound");
    expect_not_found(err, "attachment");
}

#[test]
fn history_attachment_bytes_returns_not_found_for_missing_history_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("e")).expect("add");
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("only.bin", b"present".to_vec(), false);
    })
    .expect("attach");
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("v1");
    })
    .expect("snapshot");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    // Snapshot 0 exists; ask for a far-future index.
    let err = engine
        .history_attachment_bytes(id.0, 99, "only.bin")
        .expect_err("missing history index should NotFound");
    expect_not_found(err, "attachment");
}

#[test]
fn history_attachment_bytes_returns_not_found_for_missing_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let err = engine
        .history_attachment_bytes(Uuid::new_v4(), 0, "anything.bin")
        .expect_err("missing entry should NotFound");
    expect_not_found(err, "attachment");
}

#[test]
fn history_attachment_bytes_returns_not_found_for_legacy_snapshot_without_sha() {
    // Simulate a pre-widening snapshot row by writing a snapshot_json
    // that has the attachment ref but omits `sha256_hex`. The read path
    // must surface NotFound rather than guessing by name.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("e")).expect("add");
    // Seed the live attachment so attachment_blob has the bytes (proves
    // the lookup deliberately refuses name-only fallbacks).
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("legacy.bin", b"alive".to_vec(), false);
    })
    .expect("attach");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    // Hand-stuff a legacy-shape snapshot_json row.
    let mut hex = String::with_capacity(64);
    for b in DB_KEY_BYTES {
        write!(&mut hex, "{b:02x}").expect("hex");
    }
    let conn = rusqlite::Connection::open(&path).expect("open raw");
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))
        .expect("apply key");
    let legacy_json = serde_json::json!({
        "title": "v0",
        "username": "",
        "url": "",
        "url_host": "",
        "notes": "",
        "password": "",
        "tags": [],
        "created_at": 0_i64,
        "modified_at": 0_i64,
        "accessed_at": 0_i64,
        "last_used_at": null,
        "expires_at": null,
        "icon_index": 0,
        "icon_custom_uuid": null,
        "password_strength_bucket": null,
        "password_entropy": null,
        // Legacy shape: no sha256_hex on the attachment.
        "attachments": [{ "name": "legacy.bin", "size": 5 }],
        "custom_fields": {},
    })
    .to_string();
    conn.execute(
        "INSERT INTO entry_history (entry_uuid, history_index, snapshot_json) \
         VALUES (?1, 0, ?2)",
        rusqlite::params![id.0.to_string(), legacy_json],
    )
    .expect("insert legacy");
    drop(conn);

    let engine = open_engine(&path);
    let err = engine
        .history_attachment_bytes(id.0, 0, "legacy.bin")
        .expect_err("legacy snapshot without sha should NotFound");
    expect_not_found(err, "attachment");
}
