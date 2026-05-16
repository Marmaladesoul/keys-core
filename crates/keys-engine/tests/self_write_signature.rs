//! Integration tests for [`Engine::consume_self_write_signature`]
//! (task 2.6).
//!
//! Covers the one-shot match / clear semantics, mismatch on either
//! component leaves state unchanged, and a fresh save after consume
//! records a new signature.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};

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
const COMPOSITE_PW: &[u8] = b"pw";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(COMPOSITE_PW);
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector())).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

/// Stat `path` and return `(mtime, size)` the way a file watcher would.
fn stat(path: &std::path::Path) -> (SystemTime, u64) {
    let meta = std::fs::metadata(path).expect("stat");
    (meta.modified().expect("mtime"), meta.len())
}

#[test]
fn consume_returns_false_when_no_signature_stored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let mut engine = open_engine(&db_path);

    assert!(engine.last_self_write().is_none(), "precondition");
    assert!(!engine.consume_self_write_signature(SystemTime::now(), 100));
    assert!(
        engine.last_self_write().is_none(),
        "state unchanged when nothing to consume"
    );
}

#[test]
fn consume_matches_after_save_and_returns_true() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.save_to_kdbx(&kdbx_path, &mut kdbx).expect("save");

    let (mtime, size) = stat(&kdbx_path);
    let sig = engine.last_self_write().expect("sig recorded");
    assert_eq!(sig.mtime, mtime);
    assert_eq!(sig.size, size);

    assert!(engine.consume_self_write_signature(mtime, size));
}

#[test]
fn consume_clears_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.save_to_kdbx(&kdbx_path, &mut kdbx).expect("save");
    let (mtime, size) = stat(&kdbx_path);

    assert!(engine.consume_self_write_signature(mtime, size));
    assert!(engine.last_self_write().is_none(), "signature cleared");
    assert!(
        !engine.consume_self_write_signature(mtime, size),
        "second consume with same values returns false"
    );
}

#[test]
fn consume_returns_false_on_mtime_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.save_to_kdbx(&kdbx_path, &mut kdbx).expect("save");
    let (mtime, size) = stat(&kdbx_path);
    let wrong_mtime = mtime + Duration::from_secs(60);

    assert!(!engine.consume_self_write_signature(wrong_mtime, size));
    let sig = engine
        .last_self_write()
        .expect("signature preserved on mismatch");
    assert_eq!(sig.mtime, mtime);
    assert_eq!(sig.size, size);
}

#[test]
fn consume_returns_false_on_size_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.save_to_kdbx(&kdbx_path, &mut kdbx).expect("save");
    let (mtime, size) = stat(&kdbx_path);

    assert!(!engine.consume_self_write_signature(mtime, size.wrapping_add(1)));
    let sig = engine
        .last_self_write()
        .expect("signature preserved on mismatch");
    assert_eq!(sig.size, size);
}

#[test]
fn save_after_consume_records_new_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    engine.save_to_kdbx(&kdbx_path, &mut kdbx).expect("save 1");
    let (mtime1, size1) = stat(&kdbx_path);
    assert!(engine.consume_self_write_signature(mtime1, size1));
    assert!(engine.last_self_write().is_none());

    // Sleep briefly so a re-save lands a distinguishable mtime on
    // filesystems with coarse timestamp granularity.
    std::thread::sleep(Duration::from_millis(20));

    engine.save_to_kdbx(&kdbx_path, &mut kdbx).expect("save 2");
    let new_sig = engine
        .last_self_write()
        .expect("new signature after second save");
    let (mtime2, size2) = stat(&kdbx_path);
    assert_eq!(new_sig.mtime, mtime2);
    assert_eq!(new_sig.size, size2);
}
