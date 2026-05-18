//! Integration tests for [`Engine::kdbx_state_signature`] +
//! [`Engine::record_kdbx_state_signature`] — the post-ingest /
//! post-save signature used by Keys-Mac to skip re-ingest on unlock
//! when `SQLite` already matches the on-disk KDBX.

use std::path::Path;
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

fn fresh_kdbx_at(path: &Path) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(COMPOSITE_PW);
    let kdbx = Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector()))
        .expect("create");
    // Materialise it on disk so we can stat it.
    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    std::fs::write(path, &bytes).expect("write seed");
    kdbx
}

fn open_engine(path: &Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

/// Stat `path` and return the same `(mtime_ms, byte_count)` the engine
/// builds.
fn stat_as_signature(path: &Path) -> (i64, u64) {
    let meta = std::fs::metadata(path).expect("stat");
    let mtime = meta.modified().expect("mtime");
    let ms = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("epoch")
        .as_millis();
    (i64::try_from(ms).unwrap(), meta.len())
}

#[test]
fn fresh_engine_returns_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let engine = open_engine(&db_path);

    assert!(
        engine.kdbx_state_signature().expect("query").is_none(),
        "no signature on a freshly opened engine"
    );
}

#[test]
fn record_after_ingest_matches_file_stat() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let kdbx = fresh_kdbx_at(&kdbx_path);
    let mut engine = open_engine(&db_path);

    assert!(engine.kdbx_state_signature().expect("query").is_none());

    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .record_kdbx_state_signature(&kdbx_path)
        .expect("record");

    let (mtime_ms, byte_count) = stat_as_signature(&kdbx_path);
    let sig = engine
        .kdbx_state_signature()
        .expect("query")
        .expect("signature recorded");
    assert_eq!(sig.mtime_ms, mtime_ms);
    assert_eq!(sig.byte_count, byte_count);
}

#[test]
fn save_to_kdbx_records_signature_automatically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx_at(&kdbx_path);
    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    // Save (engine writes the kdbx and should record the signature
    // for the just-written file).
    engine.save_to_kdbx(&kdbx_path, &mut kdbx).expect("save");

    let (mtime_ms, byte_count) = stat_as_signature(&kdbx_path);
    let sig = engine
        .kdbx_state_signature()
        .expect("query")
        .expect("signature after save");
    assert_eq!(sig.mtime_ms, mtime_ms);
    assert_eq!(sig.byte_count, byte_count);
}

#[test]
fn signature_survives_engine_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let kdbx = fresh_kdbx_at(&kdbx_path);
    {
        let mut engine = open_engine(&db_path);
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        engine
            .record_kdbx_state_signature(&kdbx_path)
            .expect("record");
    }

    let (mtime_ms, byte_count) = stat_as_signature(&kdbx_path);
    let engine = open_engine(&db_path);
    let sig = engine
        .kdbx_state_signature()
        .expect("query")
        .expect("signature persisted across reopen");
    assert_eq!(sig.mtime_ms, mtime_ms);
    assert_eq!(sig.byte_count, byte_count);
}

#[test]
fn signature_updates_on_re_save() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx_at(&kdbx_path);
    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.save_to_kdbx(&kdbx_path, &mut kdbx).expect("save 1");
    let sig1 = engine
        .kdbx_state_signature()
        .expect("query")
        .expect("sig 1");

    // Sleep so the second save lands a distinguishable mtime on
    // filesystems with coarse timestamp granularity.
    std::thread::sleep(Duration::from_millis(20));

    engine.save_to_kdbx(&kdbx_path, &mut kdbx).expect("save 2");
    let sig2 = engine
        .kdbx_state_signature()
        .expect("query")
        .expect("sig 2");

    // mtime should have advanced (or at least the signature should
    // reflect the now-current file stat).
    let (mtime_ms, byte_count) = stat_as_signature(&kdbx_path);
    assert_eq!(sig2.mtime_ms, mtime_ms);
    assert_eq!(sig2.byte_count, byte_count);
    assert!(
        sig2.mtime_ms >= sig1.mtime_ms,
        "second save's mtime is not earlier than the first's"
    );
}
