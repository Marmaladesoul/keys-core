//! Integration tests for the per-vault fingerprint-key infrastructure
//! (task 2.1).
//!
//! Covers the persistence of the `fingerprint_key` row in `setting`,
//! the determinism of [`Engine::fingerprint`] within a session and
//! across reopens, and the per-vault uniqueness property that makes
//! fingerprint comparison safe to share across entries inside a vault
//! while being meaningless across vaults.

use std::sync::Arc;

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use rusqlite::Connection;

#[derive(Debug)]
struct FixedKey([u8; 32]);

impl KeyProvider for FixedKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.0))
    }
}

#[derive(Debug)]
struct TestProtector([u8; 32]);

impl FieldProtector for TestProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Ok(SessionKey::from_bytes(self.0))
    }
}

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(TestProtector([0x5a; 32]))
}

/// Hex-encode 32 bytes for the `PRAGMA key = "x'…'"` form used by the
/// raw-rusqlite peeks below. Mirrors the engine's internal encoder so
/// the tests don't have to depend on a private item.
fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(s, "{b:02x}").expect("write to String");
    }
    s
}

/// Open a raw `SQLCipher` connection to `path` keyed with `key`, used
/// for direct peeks into the `setting` table.
fn raw_open(path: &std::path::Path, key: &[u8; 32]) -> Connection {
    let conn = Connection::open(path).expect("raw open");
    let stmt = format!("PRAGMA key = \"x'{}'\"", hex(key));
    conn.execute_batch(&stmt).expect("apply key");
    conn
}

fn read_fingerprint_key_row(conn: &Connection) -> Vec<u8> {
    conn.query_row(
        "SELECT value FROM setting WHERE key = 'fingerprint_key'",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .expect("fingerprint_key row exists")
}

#[test]
fn first_open_generates_fingerprint_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key_bytes = [0x11; 32];

    Engine::open(&path, &FixedKey(key_bytes), protector())
        .expect("open")
        .close()
        .expect("close");

    let raw = raw_open(&path, &key_bytes);
    let val = read_fingerprint_key_row(&raw);
    assert_eq!(val.len(), 32, "fingerprint_key must be exactly 32 bytes");
    assert!(
        val.iter().any(|&b| b != 0),
        "fingerprint_key should be random — all-zero is astronomically unlikely",
    );
}

#[test]
fn fingerprint_key_persists_across_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key_bytes = [0x22; 32];

    Engine::open(&path, &FixedKey(key_bytes), protector())
        .expect("first open")
        .close()
        .expect("close");

    let first = {
        let raw = raw_open(&path, &key_bytes);
        read_fingerprint_key_row(&raw)
    };

    Engine::open(&path, &FixedKey(key_bytes), protector())
        .expect("reopen")
        .close()
        .expect("close");

    let second = {
        let raw = raw_open(&path, &key_bytes);
        read_fingerprint_key_row(&raw)
    };

    assert_eq!(
        first, second,
        "fingerprint_key must survive reopen unchanged"
    );
}

#[test]
fn fingerprint_is_deterministic_within_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let engine = Engine::open(&path, &FixedKey([0x33; 32]), protector()).expect("open");

    let a = engine.fingerprint(b"hunter2");
    let b = engine.fingerprint(b"hunter2");

    assert_eq!(a, b);
}

#[test]
fn fingerprint_is_stable_across_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key_bytes = [0x44; 32];

    let first = {
        let engine = Engine::open(&path, &FixedKey(key_bytes), protector()).expect("first open");
        let fp = engine.fingerprint(b"correct horse battery staple");
        engine.close().expect("close");
        fp
    };

    let second = {
        let engine = Engine::open(&path, &FixedKey(key_bytes), protector()).expect("reopen");
        let fp = engine.fingerprint(b"correct horse battery staple");
        engine.close().expect("close");
        fp
    };

    assert_eq!(first, second);
}

#[test]
fn fingerprint_differs_for_different_plaintexts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let engine = Engine::open(&path, &FixedKey([0x55; 32]), protector()).expect("open");

    let a = engine.fingerprint(b"alpha");
    let b = engine.fingerprint(b"beta");

    assert_ne!(a, b);
}

#[test]
fn fingerprint_differs_across_different_vaults() {
    let dir_a = tempfile::tempdir().expect("tempdir a");
    let dir_b = tempfile::tempdir().expect("tempdir b");
    let path_a = dir_a.path().join("a.db");
    let path_b = dir_b.path().join("b.db");

    // Distinct SQLCipher keys for the two vaults — the fingerprint
    // keys are still independent regardless, but using different DB
    // keys keeps this test honest about the "different vault" framing.
    let engine_a = Engine::open(&path_a, &FixedKey([0x66; 32]), protector()).expect("open a");
    let engine_b = Engine::open(&path_b, &FixedKey([0x77; 32]), protector()).expect("open b");

    let fp_a = engine_a.fingerprint(b"x");
    let fp_b = engine_b.fingerprint(b"x");

    assert_ne!(
        fp_a, fp_b,
        "two vaults must produce different fingerprints for the same plaintext",
    );
}
