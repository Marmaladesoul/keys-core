//! Integration tests for [`Engine::attachment_bytes`] (task 3.1
//! completion).
//!
//! Covers happy-path retrieval, `NotFound` for missing attachments and
//! missing entries, and the content-addressed dedup invariant — two
//! entries sharing the same blob both read back the same bytes.

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
fn attachment_bytes_returns_blob_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("logo")).expect("add");
    let bytes = b"\x89PNG\r\n\x1a\n-not-really-but-good-enough".to_vec();
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("logo.png", bytes.clone(), false);
    })
    .expect("attach");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let read = engine
        .attachment_bytes(id.0, "logo.png")
        .expect("attachment_bytes");
    assert_eq!(read, bytes);
}

#[test]
fn attachment_bytes_returns_not_found_for_missing_attachment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(root, NewEntry::new("only-one"))
        .expect("add");
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("there.bin", b"present".to_vec(), false);
    })
    .expect("attach");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let err = engine
        .attachment_bytes(id.0, "missing.bin")
        .expect_err("missing attachment should be NotFound");
    expect_not_found(err, "attachment");
}

#[test]
fn attachment_bytes_returns_not_found_for_missing_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let err = engine
        .attachment_bytes(Uuid::new_v4(), "anything.bin")
        .expect_err("missing entry should be NotFound");
    expect_not_found(err, "attachment");
}

#[test]
fn attachment_bytes_handles_dedup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let shared = b"shared-binary-content".to_vec();

    let id_a = kdbx.add_entry(root, NewEntry::new("a")).expect("add a");
    let id_b = kdbx.add_entry(root, NewEntry::new("b")).expect("add b");

    kdbx.edit_entry(id_a, HistoryPolicy::NoSnapshot, |e| {
        e.attach("shared.bin", shared.clone(), false);
    })
    .expect("attach a");
    kdbx.edit_entry(id_b, HistoryPolicy::NoSnapshot, |e| {
        e.attach("shared.bin", shared.clone(), false);
    })
    .expect("attach b");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let read_a = engine
        .attachment_bytes(id_a.0, "shared.bin")
        .expect("attachment a");
    let read_b = engine
        .attachment_bytes(id_b.0, "shared.bin")
        .expect("attachment b");
    assert_eq!(read_a, shared);
    assert_eq!(read_b, shared);
    assert_eq!(read_a, read_b);

    // Sanity: dedup means a single blob row backs both links — open
    // the SQLCipher DB read-only via rusqlite and confirm there's
    // exactly one row in `attachment_blob`.
    engine.close().expect("close");
    let blob_count = count_attachment_blobs(&path);
    assert_eq!(blob_count, 1, "dedup expected; two blobs would be wrong");
}

/// Open the on-disk `SQLCipher` database with `rusqlite` directly and
/// count rows in `attachment_blob`. Mirrors the raw-inspection pattern
/// in `tests/history_wrap.rs`.
fn count_attachment_blobs(path: &std::path::Path) -> i64 {
    use std::fmt::Write as _;
    let conn = rusqlite::Connection::open(path).expect("open raw");
    let mut hex = String::with_capacity(64);
    for b in DB_KEY_BYTES {
        write!(&mut hex, "{b:02x}").expect("hex write");
    }
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))
        .expect("apply key");
    conn.query_row("SELECT COUNT(*) FROM attachment_blob", [], |r| r.get(0))
        .expect("count")
}
