//! Integration tests for `Engine::purge_local_data` — the engine-owned
//! teardown that destroys a removed vault's local-device data: the
//! `SQLCipher` `SQLite` mirror sidecar files on disk AND the database
//! key, the latter via the injected `KeyProvider`'s `delete_db_key`.

use std::path::PathBuf;
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
/// `purge` still removes the on-disk sidecars even when the key deletion
/// fails, and that the keystore error is surfaced.
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

/// Implements ONLY `acquire_db_key`, inheriting the trait's fail-closed
/// `delete_db_key` default — models a provider that reaches the purge
/// sequence without a real key-destruction mechanism.
#[derive(Debug)]
struct AcquireOnlyKey {
    key: [u8; 32],
}

impl KeyProvider for AcquireOnlyKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.key))
    }
    // delete_db_key: inherits the fail-closed default (Err).
}

/// Records, at the instant `delete_db_key` is invoked, whether the
/// mirror's base DB file still exists on disk — the witness for
/// key-deletion-runs-before-file-deletion (the crypto-shred ordering).
#[derive(Debug)]
struct OrderRecordingKey {
    key: [u8; 32],
    db_path: PathBuf,
    base_present_at_delete: Arc<AtomicBool>,
}

impl KeyProvider for OrderRecordingKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.key))
    }
    fn delete_db_key(&self) -> Result<(), KeyProviderError> {
        self.base_present_at_delete
            .store(self.db_path.exists(), Ordering::SeqCst);
        Ok(())
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

    let removed = Engine::purge_local_data(&path, &key).expect("purge ok");

    // A populated mirror reports at least the base DB file unlinked.
    assert!(
        removed >= 1,
        "purge of a populated mirror must report >= 1 sidecar removed, got {removed}",
    );

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

    // Resilient: the key deletion is attempted first and fails, but the
    // sidecar files are still destroyed — every step runs.
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
fn purge_with_unimplemented_delete_shreds_files_then_fails_closed() {
    // A provider that never overrides delete_db_key inherits the
    // fail-closed default. Purge must still unlink the ciphertext
    // (resilient), but must NOT report a clean success while the key
    // lives on — it surfaces the fail-closed KeyUnavailable.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key = AcquireOnlyKey { key: [0x77; 32] };

    seed_closed_mirror(&path, &key);
    assert!(path.exists());

    let err = Engine::purge_local_data(&path, &key)
        .expect_err("an unimplemented delete_db_key must fail closed");

    assert!(
        !path.exists(),
        "sidecars must be unlinked even when key deletion is unimplemented",
    );
    match err {
        EngineError::KeyProvider(KeyProviderError::KeyUnavailable(msg)) => {
            assert!(
                msg.contains("not implemented"),
                "expected the fail-closed default message, got: {msg}",
            );
        }
        other => panic!("expected KeyProvider(KeyUnavailable), got {other:?}"),
    }
}

#[test]
fn purge_deletes_key_before_unlinking_files() {
    // Key-first ordering: an interrupted purge must leave inert
    // ciphertext, not a live key beside a deleted file. Prove the key
    // deletion fires while the mirror file is still on disk.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let base_present = Arc::new(AtomicBool::new(false));
    let key = OrderRecordingKey {
        key: [0x33; 32],
        db_path: path.clone(),
        base_present_at_delete: base_present.clone(),
    };

    seed_closed_mirror(&path, &key);

    let removed = Engine::purge_local_data(&path, &key).expect("purge ok");
    assert!(removed >= 1, "a populated mirror reports >= 1 removed");
    assert!(
        base_present.load(Ordering::SeqCst),
        "delete_db_key must run BEFORE the mirror file is unlinked (key-first ordering)",
    );
    assert!(!path.exists(), "the mirror file is unlinked after the key");
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
    let removed = Engine::purge_local_data(&path, &key).expect("purge ok");
    assert!(removed >= 1, "the purged vault's own sidecar was removed");

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
    // never built a mirror) is success with a zero count — the
    // "nothing to purge" signal — and still deletes the key, so a
    // re-run of a partially-failed purge converges.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("never-existed.db");
    let deleted = Arc::new(AtomicBool::new(false));
    let key = RecordingKey {
        key: [0x55; 32],
        deleted: deleted.clone(),
    };

    let removed = Engine::purge_local_data(&path, &key).expect("purge of absent mirror is success");
    assert_eq!(
        removed, 0,
        "an absent mirror reports zero sidecars removed (the nothing-to-purge signal)",
    );
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
