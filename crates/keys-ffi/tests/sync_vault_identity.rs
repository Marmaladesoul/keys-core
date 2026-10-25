//! The reconcile vault-identity guard as the FFI surfaces it: a different
//! vault at the bound path makes `sync_with_disk` (and the peer-blob
//! `ingest_peer_kdbx`) fail with [`EngineError::VaultIdentityMismatch`],
//! writing neither the mirror nor the file — while an externally edited copy
//! of the same vault still syncs.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use keepass_core::CompositeKey;
use keepass_core::kdbx::Kdbx;
use keepass_core::model::NewEntry;
use keys_ffi::{
    Engine, EngineError, Page, SyncWithDiskFfi, VaultDbKeyProvider, VaultDbKeyProviderError,
    VaultFieldProtector, VaultProtectorError,
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

fn open_fresh_engine(db_path: &std::path::Path) -> Arc<Engine> {
    Engine::open(
        db_path.to_string_lossy().into_owned(),
        Arc::new(FixedDbKey),
        Arc::new(FixedProtector),
        None,
    )
    .expect("open engine")
}

/// Bytes of a fresh vault (its own root-group UUID) holding one entry.
fn vault_bytes(title: &str) -> Vec<u8> {
    let composite = CompositeKey::from_password(KDBX_PASSWORD.as_bytes());
    let mut kdbx = Kdbx::create_empty_v4(&composite, "test").expect("create");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new(title))
        .expect("add entry");
    kdbx.save_to_bytes().expect("save bytes")
}

/// Replace the file at `path` with `bytes`, bumping its mtime past anything
/// recorded so the next sync sees a changed file.
fn overwrite(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write");
    let file = std::fs::File::options()
        .write(true)
        .open(path)
        .expect("open for mtime");
    file.set_modified(SystemTime::now() + MTIME_BUMP)
        .expect("bump mtime");
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

/// Everything a refused sync must leave untouched, read through the seam.
#[derive(Debug, PartialEq, Eq)]
struct SeamState {
    titles: Vec<String>,
    signature: Option<keys_ffi::KdbxStateSignatureFfi>,
    persistence: keys_ffi::PersistenceStateFfi,
    parked: Vec<String>,
}

fn seam_state(engine: &Engine) -> SeamState {
    SeamState {
        titles: titles(engine),
        signature: engine.kdbx_state_signature().expect("signature"),
        persistence: engine.persistence_state().expect("persistence"),
        parked: engine.entries_with_parked_conflict().expect("parked"),
    }
}

/// A mirror bound to vault A at `vault.kdbx`, brought current by a first
/// `sync_with_disk` (the fresh-ingest correspondence point).
async fn bound_engine(dir: &std::path::Path) -> (Arc<Engine>, std::path::PathBuf) {
    let kdbx_path = dir.join("vault.kdbx");
    std::fs::write(&kdbx_path, vault_bytes("alpha")).expect("write A");
    let engine = open_fresh_engine(&dir.join("keys.db"));
    let first = engine
        .sync_with_disk(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
            None,
            None,
        )
        .await
        .expect("first sync");
    assert!(
        matches!(first, SyncWithDiskFfi::FreshIngest),
        "got {first:?}"
    );
    assert_eq!(titles(&engine), vec!["alpha".to_owned()]);
    (engine, kdbx_path)
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_with_disk_refuses_a_swapped_in_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path) = bound_engine(dir.path()).await;
    let stranger = vault_bytes("bravo");
    overwrite(&kdbx_path, &stranger);
    let before = seam_state(&engine);

    let result = engine
        .sync_with_disk(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
            None,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(EngineError::VaultIdentityMismatch { .. })),
        "got {result:?}"
    );
    assert_eq!(
        seam_state(&engine),
        before,
        "a refused sync must not move any mirror state"
    );
    assert_eq!(before.titles, vec!["alpha".to_owned()]);
    assert_eq!(
        std::fs::read(&kdbx_path).expect("read"),
        stranger,
        "the refused sync must not write back over the stranger's file"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ingest_peer_kdbx_refuses_a_different_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path) = bound_engine(dir.path()).await;
    let blob = dir.path().join("peer-blob.kdbx");
    std::fs::write(&blob, vault_bytes("bravo")).expect("write blob");
    let vault_before = std::fs::read(&kdbx_path).expect("read vault");
    let before = seam_state(&engine);

    let result = engine
        .ingest_peer_kdbx(
            "peer-device".to_owned(),
            blob.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
            None,
        )
        .await;

    assert!(
        matches!(result, Err(EngineError::VaultIdentityMismatch { .. })),
        "got {result:?}"
    );
    assert_eq!(seam_state(&engine), before);
    assert_eq!(
        std::fs::read(&kdbx_path).expect("read vault"),
        vault_before,
        "a refused peer ingest must not write the bound vault file"
    );
}

/// Control: the same vault, edited elsewhere, still syncs.
#[tokio::test(flavor = "multi_thread")]
async fn sync_with_disk_still_adopts_an_external_edit_of_the_same_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path) = bound_engine(dir.path()).await;

    let composite = CompositeKey::from_password(KDBX_PASSWORD.as_bytes());
    let mut external = Kdbx::open(&kdbx_path)
        .expect("open")
        .read_header()
        .expect("header")
        .unlock(&composite)
        .expect("unlock");
    let root = external.vault().root.id;
    external
        .add_entry(root, NewEntry::new("added-elsewhere"))
        .expect("external add");
    overwrite(&kdbx_path, &external.save_to_bytes().expect("save"));

    let result = engine
        .sync_with_disk(
            kdbx_path.to_string_lossy().into_owned(),
            KDBX_PASSWORD.to_owned(),
            None,
            None,
        )
        .await
        .expect("same-vault sync must succeed");

    assert!(
        matches!(result, SyncWithDiskFfi::Applied { .. }),
        "got {result:?}"
    );
    assert_eq!(
        titles(&engine),
        vec!["added-elsewhere".to_owned(), "alpha".to_owned()]
    );
}
