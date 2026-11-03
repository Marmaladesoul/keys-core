//! The KDF-cost gate as the FFI surfaces it: `ingest_peer_kdbx` refuses a
//! peer blob whose outer header demands a different KDF cost (its KDF
//! parameters, salt aside) from the bound vault's, with
//! [`EngineError::KdfParametersMismatch`], before deriving anything and
//! writing neither the mirror nor the file — while a replica at the same
//! cost under a fresh salt still merges.
//!
//! The refused blobs are real replicas with only the header's KDF
//! parameters rewritten, as a doc writer could plant: their header HMAC no
//! longer verifies, so a reader that derived first would fail as a wrong
//! key instead. The hostile-cost shape (gigabytes, billions of passes) is
//! the keyhole scenario `peer-kdf-cost-refused.sh`, under a watchdog; here
//! the difference is kept cheap so a regression fails rather than hangs.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::format::{FileSignature, KdfParams, VersionFields};
use keepass_core::kdbx::Kdbx;
use keepass_core::model::NewEntry;
use keys_ffi::{
    Engine, EngineError, Page, ParkConflictsResultFfi, SyncWithDiskFfi, VaultDbKeyProvider,
    VaultDbKeyProviderError, VaultFieldProtector, VaultProtectorError,
};

const DB_KEY: [u8; 32] = [0x42; 32];
const SESSION_KEY: [u8; 32] = [0x9c; 32];
const KDBX_PASSWORD: &str = "test-password";

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

fn composite() -> CompositeKey {
    CompositeKey::from_password(KDBX_PASSWORD.as_bytes())
}

fn path_string(p: &std::path::Path) -> String {
    p.to_string_lossy().into_owned()
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

/// Everything a refused ingest must leave untouched, read through the seam.
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

/// A mirror bound to a one-entry vault at `vault.kdbx`, brought current by
/// a first `sync_with_disk` (the fresh-ingest correspondence point).
async fn bound_engine(dir: &std::path::Path) -> (Arc<Engine>, std::path::PathBuf) {
    let kdbx_path = dir.join("vault.kdbx");
    let mut kdbx = Kdbx::create_empty_v4(&composite(), "test").expect("create");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("alpha"))
        .expect("add entry");
    std::fs::write(&kdbx_path, kdbx.save_to_bytes().expect("save bytes")).expect("write vault");
    let engine = open_fresh_engine(&dir.join("keys.db"));
    let first = engine
        .sync_with_disk(
            path_string(&kdbx_path),
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
    (engine, kdbx_path)
}

/// A replica of the vault at `vault`, re-saved with one entry added — a
/// peer's honest copy.
fn replica_with_entry(vault: &std::path::Path, title: &str) -> Kdbx<keepass_core::kdbx::Unlocked> {
    let mut kdbx = Kdbx::open(vault)
        .expect("open")
        .read_header()
        .expect("header")
        .unlock(&composite())
        .expect("unlock");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new(title))
        .expect("add entry");
    kdbx
}

/// `bytes` with the outer header's Argon2 pass count raised by one — the
/// salt, the rest of the header and the payload byte-for-byte as they were.
fn with_one_more_pass(bytes: Vec<u8>) -> Vec<u8> {
    let read = Kdbx::open_from_bytes(bytes)
        .expect("open")
        .read_header()
        .expect("header");
    let mut header = read.header().clone();
    let mut params = header.decode_kdf_params().expect("decode kdf");
    let KdfParams::Argon2 { iterations, .. } = &mut params else {
        panic!("create_empty_v4 vaults use Argon2, got {params:?}");
    };
    *iterations += 1;
    let VersionFields::V4 { kdf_parameters, .. } = &mut header.version_fields else {
        panic!("create_empty_v4 vaults are KDBX4");
    };
    *kdf_parameters = params.to_var_dictionary_blob().expect("encode kdf");
    let mut forged = read.header_bytes()[..FileSignature::LEN].to_vec();
    forged.extend(header.write().expect("write header"));
    forged.extend_from_slice(read.payload_bytes());
    forged
}

#[tokio::test(flavor = "multi_thread")]
async fn ingest_peer_kdbx_refuses_a_different_kdf_cost() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path) = bound_engine(dir.path()).await;
    let peer = replica_with_entry(&kdbx_path, "bravo");
    let blob = dir.path().join("peer-blob.kdbx");
    std::fs::write(
        &blob,
        with_one_more_pass(peer.save_to_bytes().expect("save peer")),
    )
    .expect("write blob");
    let vault_before = std::fs::read(&kdbx_path).expect("read vault");
    let before = seam_state(&engine);

    let result = engine
        .ingest_peer_kdbx(
            "peer-device".to_owned(),
            path_string(&blob),
            KDBX_PASSWORD.to_owned(),
            None,
        )
        .await;

    let Err(EngineError::KdfParametersMismatch { local, peer }) = result else {
        panic!("expected KdfParametersMismatch, got {result:?}");
    };
    assert!(local.contains("2 iter"), "local cost: {local}");
    assert!(peer.contains("3 iter"), "peer cost: {peer}");
    assert_eq!(seam_state(&engine), before);
    assert_eq!(
        std::fs::read(&kdbx_path).expect("read vault"),
        vault_before,
        "a refused peer ingest must not write the bound vault file"
    );
}

/// The salt is not cost: a replica re-keyed under the same password carries
/// a fresh KDF salt at the same parameters, and still merges.
#[tokio::test(flavor = "multi_thread")]
async fn ingest_peer_kdbx_merges_a_fresh_salt_at_the_same_cost() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, kdbx_path) = bound_engine(dir.path()).await;
    let mut peer = replica_with_entry(&kdbx_path, "bravo");
    let kdf_before = peer.outer_header().decode_kdf_params().expect("kdf");
    peer.rekey(&composite())
        .expect("re-key under the same password");
    assert_ne!(
        peer.outer_header().decode_kdf_params().expect("kdf"),
        kdf_before,
        "the re-key must rotate the salt, or this test proves nothing"
    );
    let blob = dir.path().join("peer-blob.kdbx");
    std::fs::write(&blob, peer.save_to_bytes().expect("save peer")).expect("write blob");

    let result = engine
        .ingest_peer_kdbx(
            "peer-device".to_owned(),
            path_string(&blob),
            KDBX_PASSWORD.to_owned(),
            None,
        )
        .await
        .expect("a same-cost replica merges");

    assert!(
        matches!(result, ParkConflictsResultFfi::Applied { .. }),
        "got {result:?}"
    );
    assert_eq!(
        titles(&engine),
        vec!["alpha".to_owned(), "bravo".to_owned()]
    );
}

/// A mirror with no recorded KDF cost — here, one never ingested from a
/// vault file — has nothing to check a peer blob against, so it refuses
/// rather than deriving at whatever cost the blob names.
#[tokio::test(flavor = "multi_thread")]
async fn ingest_peer_kdbx_refuses_when_the_mirror_records_no_kdf_cost() {
    let dir = tempfile::tempdir().unwrap();
    let (_, kdbx_path) = bound_engine(dir.path()).await;
    let blob = dir.path().join("peer-blob.kdbx");
    std::fs::copy(&kdbx_path, &blob).expect("copy replica");
    let engine = open_fresh_engine(&dir.path().join("unbound.db"));

    let result = engine
        .ingest_peer_kdbx(
            "peer-device".to_owned(),
            path_string(&blob),
            KDBX_PASSWORD.to_owned(),
            None,
        )
        .await;

    let Err(EngineError::Internal(message)) = &result else {
        panic!("expected the unrecorded-KDF refusal, got {result:?}");
    };
    assert!(
        message.contains("records no KDF parameters"),
        "got {message}"
    );
    assert!(titles(&engine).is_empty(), "nothing may merge");
}
