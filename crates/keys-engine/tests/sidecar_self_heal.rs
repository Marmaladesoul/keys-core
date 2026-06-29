//! Integration tests for the sidecar self-heal primitives —
//! [`Engine::discard_sidecar`] and [`Engine::rebuild_local_data`].
//!
//! The load-bearing invariant: `discard_sidecar` tears down the mirror
//! FILES but, unlike `purge_local_data`, leaves the keystore DB key
//! intact, so the rebuild's re-open can re-acquire it. Deleting the key
//! here would turn a recoverable stale-sidecar into a permanent "key
//! unavailable" brick — the exact failure the self-heal exists to prevent.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, EngineError, KeyProvider, KeyProviderError};
use rusqlite::Connection;

const SESSION_KEY_BYTES: [u8; 32] = [0x9c; 32];

/// A db-key provider that hands out a fixed key and records whether its
/// `delete_db_key` was ever invoked.
#[derive(Debug)]
struct RecordingKey {
    key: [u8; 32],
    deleted: Arc<AtomicBool>,
}

impl KeyProvider for RecordingKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.key))
    }
    fn delete_db_key(&self) -> Result<(), KeyProviderError> {
        self.deleted.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// A fixed-key provider (no `delete_db_key` override needed for these tests).
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
    Arc::new(TestProtector(SESSION_KEY_BYTES))
}

/// A fresh in-memory KDBX (no KDF cost) to ingest from.
fn fresh_kdbx() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector())).expect("create")
}

/// Raw-open the `SQLCipher` mirror at `path` under `key_bytes` so a test can
/// peek at its contents directly (mirrors the engine's `PRAGMA key`).
fn raw_open(path: &std::path::Path, key_bytes: &[u8; 32]) -> Connection {
    let mut hex = String::with_capacity(64);
    for b in key_bytes {
        use std::fmt::Write as _;
        write!(&mut hex, "{b:02x}").expect("hex");
    }
    let conn = Connection::open(path).expect("raw open");
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))
        .expect("apply key");
    conn
}

#[test]
fn discard_sidecar_removes_files_but_keeps_the_db_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let deleted = Arc::new(AtomicBool::new(false));
    let key = RecordingKey {
        key: [0x42; 32],
        deleted: deleted.clone(),
    };

    // Seed a populated mirror, then release it.
    {
        let mut engine = Engine::open(&path, &key, protector(), None).expect("open");
        engine.ingest_from_kdbx(&fresh_kdbx()).expect("ingest");
        engine.close().expect("close");
    }
    assert!(path.exists(), "sidecar should exist before discard");

    let discarded = Engine::discard_sidecar(&path).expect("discard ok");
    assert!(
        discarded >= 1,
        "a populated mirror discards >= 1 file, got {discarded}",
    );
    assert!(
        !path.exists(),
        "the sidecar DB file must be gone after discard"
    );

    // THE load-bearing invariant — the difference from `purge_local_data`:
    // the keystore DB key was NOT deleted, so the rebuild's re-open can
    // re-acquire it. Deleting it here would brick the vault.
    assert!(
        !deleted.load(Ordering::SeqCst),
        "discard_sidecar must NOT delete the keystore DB key (that is purge_local_data's job)",
    );
}

#[test]
fn discard_sidecar_is_absent_tolerant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nonexistent.db");
    let discarded = Engine::discard_sidecar(&path).expect("discard ok on absent path");
    assert_eq!(
        discarded, 0,
        "discarding a non-existent mirror removes nothing",
    );
}

#[test]
fn rebuild_local_data_recovers_a_stale_keyed_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");

    // Seed a mirror sealed under key A.
    let key_a = FixedKey([0x42; 32]);
    {
        let mut engine = Engine::open(&path, &key_a, protector(), None).expect("open A");
        engine.ingest_from_kdbx(&fresh_kdbx()).expect("ingest A");
        engine.close().expect("close A");
    }

    // The keystore now hands back a DIFFERENT key (rotated / re-minted).
    // The ordinary open must fail with the recoverable WrongKey signal.
    let key_b_bytes = [0x11; 32];
    let key_b = FixedKey(key_b_bytes);
    let err = Engine::open(&path, &key_b, protector(), None).expect_err("stale key must fail open");
    assert!(
        matches!(err, EngineError::WrongKey),
        "a stale db key opens as WrongKey, got {err:?}",
    );
    assert!(
        err.is_recoverable_sidecar_failure(),
        "WrongKey at open must classify as a recoverable sidecar failure",
    );

    // Rebuild from the KDBX under key B: discard the stale sidecar, mint a
    // fresh one under B, re-ingest. The key is never deleted.
    let (engine, discarded) =
        Engine::rebuild_local_data(&path, &key_b, protector(), None, &fresh_kdbx())
            .expect("rebuild");
    assert!(
        discarded >= 1,
        "rebuild discards the stale sidecar (>= 1 file), got {discarded}",
    );
    engine.close().expect("close rebuilt");

    // The rebuilt sidecar is now sealed under key B and repopulated: a
    // fresh ordinary open under B succeeds (no second heal needed)...
    Engine::open(&path, &key_b, protector(), None).expect("rebuilt sidecar opens under key B");

    // ...and the root group from the ingested KDBX actually landed.
    let raw = raw_open(&path, &key_b_bytes);
    let groups: i64 = raw
        .query_row("SELECT COUNT(*) FROM \"group\"", [], |r| r.get(0))
        .expect("count groups");
    assert_eq!(
        groups, 1,
        "the rebuilt mirror must hold the ingested root group"
    );
}
