//! Integration tests for `Engine::purge_local_data` — the engine-owned
//! teardown that destroys a removed vault's local-device data: the
//! `SQLCipher` `SQLite` mirror sidecar files on disk AND the database
//! key, the latter via the injected `KeyProvider`'s `delete_db_key`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, EngineError, KeyProvider, KeyProviderError};

/// A db-key provider that hands out a fixed key and records whether its
/// `delete_db_key` was invoked — so a test can assert the engine drove
/// the key-deletion half of teardown.
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

/// Opens fine (fixed key) but refuses the key deletion — used to prove
/// `purge` still removes the on-disk sidecars before it fails, and that
/// the keystore error is surfaced.
#[derive(Debug)]
struct FailingDeleteKey {
    key: [u8; 32],
}

impl KeyProvider for FailingDeleteKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.key))
    }
    fn delete_db_key(&self) -> Result<(), KeyProviderError> {
        Err(KeyProviderError::KeyUnavailable("keystore locked".into()))
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

/// Open then close an engine at `path` so the `SQLCipher` mirror file
/// is real on disk (the open path's WAL switch + migrations write
/// pages), with the connection released — the state a vault is in at
/// teardown time.
fn seed_closed_mirror(path: &std::path::Path, key: &dyn KeyProvider) {
    let engine = Engine::open(path, key, protector(), None).expect("open");
    engine.close().expect("close");
}

#[test]
fn purge_destroys_sidecar_files_and_invokes_key_deletion() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let deleted = Arc::new(AtomicBool::new(false));
    let key = RecordingKey {
        key: [0x42; 32],
        deleted: deleted.clone(),
    };

    seed_closed_mirror(&path, &key);
    assert!(path.exists(), "mirror sidecar should exist before purge");

    Engine::purge_local_data(&path, &key).expect("purge ok");

    // The DB file and its WAL-mode siblings are gone.
    assert!(!path.exists(), "DB file must be gone after purge");
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = sibling(&path, suffix);
        assert!(
            !sidecar.exists(),
            "sidecar {} must be gone after purge",
            sidecar.display(),
        );
    }

    // The key deletion was driven through the provider.
    assert!(
        deleted.load(Ordering::SeqCst),
        "purge must invoke the key provider's delete_db_key",
    );
}

#[test]
fn purge_removes_files_then_surfaces_key_deletion_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key = FailingDeleteKey { key: [0x24; 32] };

    seed_closed_mirror(&path, &key);
    assert!(path.exists());

    let err = Engine::purge_local_data(&path, &key).expect_err("key deletion failure must surface");

    // Resilient ordering: the sidecar files are still destroyed even
    // though the key deletion failed — destruction is best-effort and
    // attempts every step.
    assert!(
        !path.exists(),
        "purge must remove the sidecar even when key deletion fails",
    );
    // ...and the keystore error is surfaced for the caller to retry.
    match err {
        EngineError::KeyProvider(KeyProviderError::KeyUnavailable(msg)) => {
            assert_eq!(msg, "keystore locked");
        }
        other => panic!("expected KeyProvider error, got {other:?}"),
    }
}

#[test]
fn purge_only_removes_its_own_files_not_the_directory() {
    // On a real client many vaults' sidecars share one container
    // directory, so purge must never remove the directory — only its
    // own files. A sibling file left beside the mirror must survive.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let bystander = dir.path().join("another-vault.db");
    std::fs::write(&bystander, b"not mine").expect("write bystander");

    let deleted = Arc::new(AtomicBool::new(false));
    let key = RecordingKey {
        key: [0x13; 32],
        deleted: deleted.clone(),
    };
    seed_closed_mirror(&path, &key);
    Engine::purge_local_data(&path, &key).expect("purge ok");

    assert!(!path.exists(), "the purged vault's sidecar must be gone");
    assert!(
        bystander.exists(),
        "a neighbouring vault's sidecar must be untouched",
    );
    assert!(
        dir.path().exists(),
        "the shared container directory must survive purge",
    );
}

#[test]
fn purge_is_absent_tolerant_and_idempotent() {
    // A purge with nothing on disk (already-removed, or a vault that
    // never built a mirror) is success, and still deletes the key —
    // so a re-run of a partially-failed purge converges.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("never-existed.db");
    let deleted = Arc::new(AtomicBool::new(false));
    let key = RecordingKey {
        key: [0x55; 32],
        deleted: deleted.clone(),
    };

    Engine::purge_local_data(&path, &key).expect("purge of absent mirror is success");
    assert!(
        deleted.load(Ordering::SeqCst),
        "key deletion still runs even when no sidecar files are present",
    );
}

/// The sibling of `base` with `suffix` appended to its filename (no
/// separating dot), matching `SQLite`'s WAL-mode naming.
fn sibling(base: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut os = base.as_os_str().to_owned();
    os.push(suffix);
    std::path::PathBuf::from(os)
}
