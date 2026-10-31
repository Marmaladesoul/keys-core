//! The test-vault kind gate as the FFI surfaces it: a replica of the bound
//! vault whose test-vault marker differs from the mirror's makes the peer-blob
//! `ingest_peer_kdbx`, `sync_with_disk` and the save path fail with
//! [`EngineError::TestVaultMarkerMismatch`], writing neither the mirror nor
//! the file — while two test-vault replicas still merge. Marking goes through
//! the file-level `mark_test_vault_file`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use keepass_core::CompositeKey;
use keepass_core::kdbx::Kdbx;
use keepass_core::model::NewEntry;
use keys_ffi::{
    Engine, EngineError, Page, SyncWithDiskFfi, VaultDbKeyProvider, VaultDbKeyProviderError,
    VaultFieldProtector, VaultProtectorError, mark_test_vault_file,
};

const DB_KEY: [u8; 32] = [0x42; 32];
const SESSION_KEY: [u8; 32] = [0x9c; 32];
const KDBX_PASSWORD: &str = "test-password";

/// How far past the recorded signature a rewritten file's mtime is pushed,
/// so `sync_with_disk` can't mistake the rewrite for the file it last saw.
const MTIME_BUMP: Duration = Duration::from_secs(5);

struct FixedDbKey;
impl VaultDbKeyProvider for FixedDbKey {
    fn acquire_db_key(&self) -> Result<Vec<u8>, VaultDbKeyProviderError> {
        Ok(DB_KEY.to_vec())
    }
    fn delete_db_key(&self) -> Result<(), VaultDbKeyProviderError> {
        Ok(())
    }
}

struct FixedProtector;
impl VaultFieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
        Ok(SESSION_KEY.to_vec())
    }
}

fn path_string(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

async fn mark(path: &std::path::Path, marked: bool) {
    mark_test_vault_file(
        path_string(path),
        KDBX_PASSWORD.to_owned(),
        None,
        marked,
        None,
    )
    .await
    .expect("mark file");
}

fn titles(engine: &Engine) -> Vec<String> {
    let mut t: Vec<String> = engine
        .list_entries(
            None,
            Page {
                offset: 0,
                limit: 100,
            },
        )
        .expect("list")
        .into_iter()
        .map(|e| e.title)
        .collect();
    t.sort();
    t
}

/// A mirror bound to a fresh vault at `vault.kdbx` (a test vault iff
/// `marked`), plus a byte-copy of that vault at `copy.kdbx`.
async fn bound_engine(
    dir: &std::path::Path,
    marked: bool,
) -> (Arc<Engine>, std::path::PathBuf, std::path::PathBuf) {
    let kdbx_path = dir.join("vault.kdbx");
    let composite = CompositeKey::from_password(KDBX_PASSWORD.as_bytes());
    let mut kdbx = Kdbx::create_empty_v4(&composite, "test").expect("create");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("alpha"))
        .expect("add entry");
    std::fs::write(&kdbx_path, kdbx.save_to_bytes().expect("save")).expect("write");
    if marked {
        mark(&kdbx_path, true).await;
    }
    let copy = dir.join("copy.kdbx");
    std::fs::copy(&kdbx_path, &copy).expect("copy");

    let engine = Engine::open(
        path_string(&dir.join("keys.db")),
        Arc::new(FixedDbKey),
        Arc::new(FixedProtector),
        None,
    )
    .expect("open engine");
    engine
        .sync_with_disk(
            path_string(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            None,
            None,
        )
        .await
        .expect("first sync");
    assert_eq!(engine.is_test_vault().expect("kind"), marked);
    (engine, kdbx_path, copy)
}

fn assert_mismatch<T: std::fmt::Debug>(result: Result<T, EngineError>, local: bool, replica: bool) {
    match result {
        Err(EngineError::TestVaultMarkerMismatch {
            local_is_test,
            replica_is_test,
        }) => assert_eq!((local_is_test, replica_is_test), (local, replica)),
        other => panic!("expected TestVaultMarkerMismatch, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ingest_peer_kdbx_refuses_a_replica_of_the_other_kind() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path, copy) = bound_engine(dir.path(), false).await;
    mark(&copy, true).await;
    let vault_before = std::fs::read(&kdbx_path).expect("read");

    let result = engine
        .ingest_peer_kdbx(
            "peer-device".to_owned(),
            path_string(&copy),
            KDBX_PASSWORD.to_owned(),
            None,
        )
        .await;

    assert_mismatch(result, false, true);
    assert_eq!(std::fs::read(&kdbx_path).expect("read"), vault_before);
    assert!(!engine.is_test_vault().expect("kind"));
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_with_disk_refuses_the_file_changing_kind() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path, _) = bound_engine(dir.path(), true).await;
    mark(&kdbx_path, false).await;
    let file = std::fs::File::options()
        .write(true)
        .open(&kdbx_path)
        .expect("open");
    file.set_modified(SystemTime::now() + MTIME_BUMP)
        .expect("bump mtime");
    let unmarked = std::fs::read(&kdbx_path).expect("read");

    let result = engine
        .sync_with_disk(
            path_string(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            None,
            None,
        )
        .await;

    assert_mismatch(result, true, false);
    assert_eq!(std::fs::read(&kdbx_path).expect("read"), unmarked);
    assert!(engine.is_test_vault().expect("kind"));
}

/// With the engine already open when the other kind's copy lands at the
/// path, a save is refused and the file is untouched.
#[tokio::test(flavor = "multi_thread")]
async fn save_refuses_to_overwrite_the_other_kind() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path, copy) = bound_engine(dir.path(), true).await;
    mark(&copy, false).await;
    std::fs::copy(&copy, &kdbx_path).expect("swap in");
    let unmarked = std::fs::read(&kdbx_path).expect("read");

    let result = engine
        .save_to_kdbx_with_keyfile(
            path_string(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            None,
            None,
        )
        .await;

    assert_mismatch(result, true, false);
    assert_eq!(std::fs::read(&kdbx_path).expect("read"), unmarked);
}

/// Control: two test-vault replicas of one vault still merge.
#[tokio::test(flavor = "multi_thread")]
async fn two_test_vault_replicas_still_merge() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path, copy) = bound_engine(dir.path(), true).await;
    let composite = CompositeKey::from_password(KDBX_PASSWORD.as_bytes());
    let mut replica = Kdbx::open(&copy)
        .expect("open")
        .read_header()
        .expect("header")
        .unlock(&composite)
        .expect("unlock");
    let root = replica.vault().root.id;
    replica
        .add_entry(root, NewEntry::new("from-replica"))
        .expect("add");
    std::fs::write(&copy, replica.save_to_bytes().expect("save")).expect("write");

    engine
        .ingest_peer_kdbx(
            "peer-device".to_owned(),
            path_string(&copy),
            KDBX_PASSWORD.to_owned(),
            None,
        )
        .await
        .expect("same-kind replicas must merge");
    assert_eq!(
        titles(&engine),
        vec!["alpha".to_owned(), "from-replica".to_owned()]
    );

    let saved = engine
        .sync_with_disk(
            path_string(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            None,
            None,
        )
        .await
        .expect("write back");
    assert!(
        !matches!(saved, SyncWithDiskFfi::FreshIngest),
        "got {saved:?}"
    );
}
