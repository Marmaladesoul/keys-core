//! A vault file whose root group has no UUID (keepass-core decodes an absent
//! `<UUID>` as nil) is given an identity on first ingest, through the seam:
//! the mirror owes the file that identity, the first save writes it, and the
//! writer's identity gate lets that one write through only onto the very file
//! the identity was stamped from — never onto a different nil-root vault.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{GroupId, NewEntry};
use keys_engine::identity::stamped_root_uuid;
use keys_ffi::{
    Engine, EngineError, SyncWithDiskFfi, VaultDbKeyProvider, VaultDbKeyProviderError,
    VaultFieldProtector, VaultIdentityVerdict, VaultProtectorError, verify_vault_identity,
};
use uuid::Uuid;

const DB_KEY: [u8; 32] = [0x42; 32];
const SESSION_KEY: [u8; 32] = [0x9c; 32];
const KDBX_PASSWORD: &str = "test-password";

/// How far past the recorded signature a touched file's mtime is pushed, so
/// `sync_with_disk` sees a changed file.
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

fn open_fresh_engine(db_path: &std::path::Path) -> Arc<Engine> {
    Engine::open(
        db_path.to_string_lossy().into_owned(),
        Arc::new(FixedDbKey),
        Arc::new(FixedProtector),
        None,
    )
    .expect("open engine")
}

fn unlock(bytes: Vec<u8>) -> Kdbx<Unlocked> {
    Kdbx::open_from_bytes(bytes)
        .and_then(Kdbx::read_header)
        .and_then(|k| k.unlock(&CompositeKey::from_password(KDBX_PASSWORD.as_bytes())))
        .expect("unlock")
}

/// Bytes of a vault holding one entry whose root group has no UUID.
fn nil_root_vault_bytes(title: &str) -> Vec<u8> {
    let composite = CompositeKey::from_password(KDBX_PASSWORD.as_bytes());
    let mut kdbx = Kdbx::create_empty_v4(&composite, "test").expect("create");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new(title))
        .expect("add entry");
    let mut vault = kdbx.vault().clone();
    vault.root.id = GroupId(Uuid::nil());
    kdbx.replace_vault(vault);
    let bytes = kdbx.save_to_bytes().expect("save bytes");
    assert!(
        unlock(bytes.clone()).vault().root.id.0.is_nil(),
        "fixture must round-trip with a nil root"
    );
    bytes
}

/// The identity a nil-root file's bytes stamp.
fn stamp_of(bytes: &[u8]) -> Uuid {
    stamped_root_uuid(&unlock(bytes.to_vec()).outer_header().master_seed.0)
}

fn file_root(path: &std::path::Path) -> Uuid {
    unlock(std::fs::read(path).expect("read")).vault().root.id.0
}

fn path_str(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

/// An engine bound to the nil-root vault at `vault.kdbx` by a first
/// `sync_with_disk`.
async fn bound_to_nil_root(
    dir: &std::path::Path,
    bytes: &[u8],
) -> (Arc<Engine>, std::path::PathBuf) {
    let kdbx_path = dir.join("vault.kdbx");
    std::fs::write(&kdbx_path, bytes).expect("write vault");
    let engine = open_fresh_engine(&dir.join("keys.db"));
    let first = engine
        .sync_with_disk(path_str(&kdbx_path), KDBX_PASSWORD.to_owned(), None, None)
        .await
        .expect("first sync");
    assert!(
        matches!(first, SyncWithDiskFfi::FreshIngest),
        "got {first:?}"
    );
    (engine, kdbx_path)
}

#[tokio::test(flavor = "multi_thread")]
async fn first_save_writes_the_stamped_identity_into_a_nil_root_file() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = nil_root_vault_bytes("alpha");
    let stamp = stamp_of(&bytes);
    let (engine, kdbx_path) = bound_to_nil_root(dir.path(), &bytes).await;

    assert!(
        engine.persistence_state().expect("persistence").is_dirty,
        "the mirror owes the file its new identity"
    );
    assert!(
        file_root(&kdbx_path).is_nil(),
        "ingest alone must not write the file"
    );

    engine
        .save_to_kdbx(path_str(&kdbx_path), KDBX_PASSWORD.to_owned(), None)
        .await
        .expect("the stamping save is let through");

    assert_eq!(file_root(&kdbx_path), stamp);
    assert!(!engine.persistence_state().expect("persistence").is_dirty);

    // From here the file carries the identity: ordinary saves and syncs.
    engine
        .save_to_kdbx(path_str(&kdbx_path), KDBX_PASSWORD.to_owned(), None)
        .await
        .expect("a later save");
    let again = engine
        .sync_with_disk(path_str(&kdbx_path), KDBX_PASSWORD.to_owned(), None, None)
        .await
        .expect("sync after stamping");
    assert!(matches!(again, SyncWithDiskFfi::UpToDate), "got {again:?}");
}

/// Two devices that ingest the same unstamped file mint the same identity, so
/// whichever writes the stamp first, the other still recognises the file.
#[tokio::test(flavor = "multi_thread")]
async fn every_device_ingesting_the_same_nil_root_file_stamps_the_same_identity() {
    let bytes = nil_root_vault_bytes("alpha");
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let (first, first_path) = bound_to_nil_root(first_dir.path(), &bytes).await;
    let (second, second_path) = bound_to_nil_root(second_dir.path(), &bytes).await;

    first
        .save_to_kdbx(path_str(&first_path), KDBX_PASSWORD.to_owned(), None)
        .await
        .expect("first device stamps");
    // The second device's copy of the vault file is now the stamped one.
    std::fs::copy(&first_path, &second_path).expect("propagate");

    second
        .save_to_kdbx(path_str(&second_path), KDBX_PASSWORD.to_owned(), None)
        .await
        .expect("the second device's mirror is the same vault");
    assert_eq!(file_root(&second_path), stamp_of(&bytes));
}

/// The stamp vouches only for the file it came from: a different nil-root
/// vault at the bound path is refused by save and re-key, its bytes untouched.
#[tokio::test(flavor = "multi_thread")]
async fn writers_refuse_a_different_nil_root_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path) = bound_to_nil_root(dir.path(), &nil_root_vault_bytes("alpha")).await;
    let stranger = nil_root_vault_bytes("bravo");
    std::fs::write(&kdbx_path, &stranger).expect("swap in a stranger");

    let saved = engine
        .save_to_kdbx(path_str(&kdbx_path), KDBX_PASSWORD.to_owned(), None)
        .await;
    assert!(
        matches!(saved, Err(EngineError::VaultIdentityMismatch { .. })),
        "got {saved:?}"
    );
    let rekeyed = engine
        .rekey_to_kdbx(
            path_str(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            "new-password".to_owned(),
            None,
        )
        .await;
    assert!(
        matches!(rekeyed, Err(EngineError::VaultIdentityMismatch { .. })),
        "got {rekeyed:?}"
    );
    assert_eq!(std::fs::read(&kdbx_path).expect("read"), stranger);
    assert!(
        engine.persistence_state().expect("persistence").is_dirty,
        "the refused writes leave the stamp still owed"
    );
}

/// Before the stamp is flushed, the file the identity came from is still this
/// vault to a reconcile: an mtime-only change (a re-download, a `touch`) syncs
/// as the same vault, and the owed stamp still lands afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn a_touch_only_change_before_the_flush_reconciles_as_the_same_vault() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = nil_root_vault_bytes("alpha");
    let (engine, kdbx_path) = bound_to_nil_root(dir.path(), &bytes).await;
    std::fs::File::options()
        .write(true)
        .open(&kdbx_path)
        .expect("open for mtime")
        .set_modified(SystemTime::now() + MTIME_BUMP)
        .expect("bump mtime");

    engine
        .sync_with_disk(path_str(&kdbx_path), KDBX_PASSWORD.to_owned(), None, None)
        .await
        .expect("the stamped-from file reconciles as the same vault");
    engine
        .save_to_kdbx(path_str(&kdbx_path), KDBX_PASSWORD.to_owned(), None)
        .await
        .expect("the owed stamp lands");
    assert_eq!(file_root(&kdbx_path), stamp_of(&bytes));
}

/// A relink verify reads a file's identity the way the ingest does, so the
/// unflushed nil-root file matches the identity stamped from it, and a
/// different nil-root vault doesn't.
#[test]
fn relink_verify_reads_a_nil_root_files_stamped_identity() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = nil_root_vault_bytes("alpha");
    let own = dir.path().join("own.kdbx");
    let other = dir.path().join("other.kdbx");
    std::fs::write(&own, &bytes).expect("write own");
    std::fs::write(&other, nil_root_vault_bytes("bravo")).expect("write other");
    let verify = |path: &std::path::Path| {
        verify_vault_identity(
            path_str(path),
            KDBX_PASSWORD.to_owned(),
            None,
            stamp_of(&bytes).to_string(),
        )
        .expect("verify")
    };

    assert_eq!(verify(&own), VaultIdentityVerdict::Match);
    assert_eq!(verify(&other), VaultIdentityVerdict::Mismatch);
}
