//! The vault-identity guard: a mirror refuses to merge a KDBX that is a
//! **different vault** (different root-group UUID), and the refusal is
//! all-or-nothing — no mirror state moves. (The write-side gate — save /
//! re-key over a different vault's file — is exercised at the FFI seam,
//! where the template is the file at the path; see keys-ffi
//! `tests/sync_vault_identity.rs`.)
//!
//! Covers every peer-ingest entry point — the disk-watcher reconcile
//! ([`Engine::reconcile_with_disk_park_conflicts`]), the per-device peer blob
//! ([`Engine::ingest_peer_from_kdbx`]) and the in-memory peer vault
//! ([`Engine::ingest_peer`]) — plus the control: an externally edited copy
//! of the SAME vault still reconciles.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{EntryId, HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, Engine, EngineError, KeyProvider, KeyProviderError, Pagination, ParkConflictsResult,
};

// ── Fixtures (inlined per the `tests/` posture — see parked_conflicts.rs) ──

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
const PASSWORD: &[u8] = b"pw";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(PASSWORD)
}

/// A fresh vault (its own random root-group UUID) holding one entry.
fn vault_with_entry(title: &str) -> Kdbx<Unlocked> {
    let mut kdbx = Kdbx::create_empty_v4_with_protector(&composite(), "test", Some(protector()))
        .expect("create");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new(title))
        .expect("seed entry");
    kdbx
}

fn reopen_kdbx(path: &std::path::Path) -> Kdbx<Unlocked> {
    Kdbx::open(path)
        .expect("open kdbx")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock kdbx")
}

struct Fixture {
    dir: tempfile::TempDir,
    kdbx_path: std::path::PathBuf,
    engine: Engine,
    /// Root-group UUID of the vault the mirror was ingested from.
    root: uuid::Uuid,
}

/// Vault A ingested into a mirror and saved to `vault.kdbx`, then given an
/// UNSAVED local edit — so the refusal must also leave a dirty watermark
/// exactly as it found it.
fn fixture() -> Fixture {
    fixture_of_kind(false)
}

/// [`fixture`], with the vault a test vault (`marked`) from the start — a
/// mirror's kind is fixed, so it is set on the vault before the ingest.
fn fixture_of_kind(marked: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx = vault_with_entry("alpha");
    if marked {
        let mut vault = kdbx.vault().clone();
        keys_engine::test_vault::set_marked(&mut vault, true);
        kdbx.replace_vault(vault);
    }
    let root = kdbx.vault().root.id.0;
    let mut engine =
        Engine::open(&db_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("initial save");
    let seed = titles(&engine);
    assert_eq!(seed, vec!["alpha".to_owned()]);
    let uuid = engine.list_entries(None, Pagination::all()).expect("list")[0].uuid;
    engine
        .set_tags(uuid, vec!["pending".into()])
        .expect("unsaved local edit");
    assert!(engine.persistence_state().expect("state").is_dirty());
    Fixture {
        dir,
        kdbx_path,
        engine,
        root,
    }
}

fn titles(engine: &Engine) -> Vec<String> {
    let mut t: Vec<String> = engine
        .list_entries(None, Pagination::all())
        .expect("list")
        .into_iter()
        .map(|e| e.title)
        .collect();
    t.sort();
    t
}

/// Everything a refused reconcile must leave untouched.
#[derive(Debug, PartialEq, Eq)]
struct MirrorState {
    titles: Vec<String>,
    digest: [u8; 32],
    persistence: keys_engine::PersistenceState,
    signature: Option<keys_engine::KdbxStateSignature>,
    parked: Vec<uuid::Uuid>,
}

fn mirror_state(engine: &Engine) -> MirrorState {
    MirrorState {
        titles: titles(engine),
        digest: engine.content_digest().expect("digest"),
        persistence: engine.persistence_state().expect("state"),
        signature: engine.kdbx_state_signature().expect("signature"),
        parked: engine.entries_with_parked_conflict().expect("parked"),
    }
}

/// Write a DIFFERENT vault (fresh root-group UUID, same password) to `path`.
/// Returns its root-group UUID and the exact bytes written.
fn write_stranger(path: &std::path::Path) -> (uuid::Uuid, Vec<u8>) {
    let stranger = vault_with_entry("bravo");
    let root = stranger.vault().root.id.0;
    let bytes = stranger.save_to_bytes().expect("save stranger");
    std::fs::write(path, &bytes).expect("write stranger");
    (root, bytes)
}

fn assert_identity_mismatch(
    result: Result<ParkConflictsResult, EngineError>,
    expected: uuid::Uuid,
    found: uuid::Uuid,
) {
    match result {
        Err(EngineError::VaultIdentityMismatch {
            expected: e,
            found: f,
        }) => {
            assert_eq!(e, expected, "`expected` must name the mirror's root");
            assert_eq!(f, found, "`found` must name the offered file's root");
        }
        other => panic!("expected VaultIdentityMismatch, got {other:?}"),
    }
}

// ── Tests ──

/// The disk-watcher path: a different vault swapped in at the watched path
/// is refused, and neither the mirror nor the file moves.
#[test]
fn reconcile_refuses_a_different_vault_and_touches_nothing() {
    let mut f = fixture();
    let (stranger_root, stranger_bytes) = write_stranger(&f.kdbx_path);
    assert_ne!(stranger_root, f.root);
    let before = mirror_state(&f.engine);

    let result =
        f.engine
            .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now());

    assert_identity_mismatch(result, f.root, stranger_root);
    assert_eq!(
        mirror_state(&f.engine),
        before,
        "a refused reconcile must not move any mirror state"
    );
    assert_eq!(
        std::fs::read(&f.kdbx_path).expect("read"),
        stranger_bytes,
        "a refused reconcile must not write the file"
    );
}

/// The per-device peer-blob path refuses a different vault the same way.
#[test]
fn peer_blob_ingest_refuses_a_different_vault() {
    let mut f = fixture();
    let blob = f.dir.path().join("peer-blob.kdbx");
    let (stranger_root, _) = write_stranger(&blob);
    let before = mirror_state(&f.engine);

    let result = f
        .engine
        .ingest_peer_from_kdbx(&blob, &composite(), "peer-device");

    assert_identity_mismatch(result, f.root, stranger_root);
    assert_eq!(mirror_state(&f.engine), before);
}

/// The in-memory peer-vault entry point (the transport hands a decoded
/// vault) is gated too — it is the choke point the file paths share.
#[test]
fn in_memory_peer_ingest_refuses_a_different_vault() {
    let mut f = fixture();
    let stranger = vault_with_entry("bravo");
    let stranger_root = stranger.vault().root.id.0;
    let before = mirror_state(&f.engine);

    let result = f.engine.ingest_peer("peer-device", stranger.vault());

    match result {
        Err(EngineError::VaultIdentityMismatch { expected, found }) => {
            assert_eq!((expected, found), (f.root, stranger_root));
        }
        other => panic!("expected VaultIdentityMismatch, got {other:?}"),
    }
    assert_eq!(mirror_state(&f.engine), before);
}

/// Control: an externally edited copy of the SAME vault (same root, new
/// content) still reconciles — the guard must not over-refuse.
#[test]
fn reconcile_still_merges_an_external_edit_of_the_same_vault() {
    let mut f = fixture();
    let uuid = f
        .engine
        .list_entries(None, Pagination::all())
        .expect("list")[0]
        .uuid;
    let mut external = reopen_kdbx(&f.kdbx_path);
    assert_eq!(external.vault().root.id.0, f.root);
    external
        .edit_entry(EntryId(uuid), HistoryPolicy::Snapshot, |e| {
            e.set_title("alpha-renamed");
        })
        .expect("disk edit");
    let bytes = external.save_to_bytes().expect("save");
    std::fs::write(&f.kdbx_path, &bytes).expect("write");

    let result = f
        .engine
        .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now())
        .expect("same-vault reconcile must succeed");

    assert!(
        matches!(result, ParkConflictsResult::Applied { .. }),
        "the external edit should be applied, got {result:?}"
    );
    assert_eq!(titles(&f.engine), vec!["alpha-renamed".to_owned()]);
}

/// A different vault holding nothing under its root (a fresh, root-only
/// database) offers the merge no rows to trip over, so without the identity
/// gate it "reconciles" as `NoChange` — the stranger is silently accepted as
/// this vault's file, and the mirror's next save overwrites it. The gate
/// refuses it like any other different vault.
#[test]
fn reconcile_refuses_an_empty_different_vault() {
    let mut f = fixture();
    let empty = Kdbx::create_empty_v4_with_protector(&composite(), "other", Some(protector()))
        .expect("create");
    assert!(empty.vault().root.groups.is_empty() && empty.vault().root.entries.is_empty());
    let empty_root = empty.vault().root.id.0;
    std::fs::write(&f.kdbx_path, empty.save_to_bytes().expect("save")).expect("write");
    let before = mirror_state(&f.engine);

    let result =
        f.engine
            .reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now());

    assert_identity_mismatch(result, f.root, empty_root);
    assert_eq!(mirror_state(&f.engine), before);
}

/// The identity verdict is reached before the mirror is projected, so it
/// stays definite even when projecting would fail. Here the mirror is
/// reopened under a rotated session key — every sealed field is
/// unreadable — and a different vault at the path must still come back as
/// `VaultIdentityMismatch`, not a projection/unwrap failure that a consumer
/// might answer by rebuilding the mirror from the file at the path.
#[test]
fn identity_verdict_precedes_a_failing_projection() {
    let f = fixture();
    let db_path = f.dir.path().join("keys.db");
    drop(f.engine);
    let rotated: Arc<dyn FieldProtector> = Arc::new(FixedProtector([0x11; 32]));
    let mut engine =
        Engine::open(&db_path, &FixedKey(DB_KEY_BYTES), rotated, None).expect("reopen engine");
    assert!(
        engine.content_digest().is_err(),
        "precondition: projection fails under the rotated session key"
    );
    let (stranger_root, _) = write_stranger(&f.kdbx_path);

    let result =
        engine.reconcile_with_disk_park_conflicts(&f.kdbx_path, &composite(), chrono::Utc::now());

    assert_identity_mismatch(result, f.root, stranger_root);
}

/// The public identity primitive writers gate on: it accepts this mirror's
/// own root and refuses any other (naming both), writing nothing.
#[test]
fn ensure_same_vault_accepts_own_root_and_names_a_stranger() {
    let f = fixture();
    let before = mirror_state(&f.engine);
    f.engine
        .ensure_same_vault(f.root)
        .expect("own root is this vault");

    let stranger = uuid::Uuid::new_v4();
    match f.engine.ensure_same_vault(stranger) {
        Err(EngineError::VaultIdentityMismatch { expected, found }) => {
            assert_eq!((expected, found), (f.root, stranger));
        }
        other => panic!("expected VaultIdentityMismatch, got {other:?}"),
    }
    assert_eq!(mirror_state(&f.engine), before);
}

/// A replica of THIS vault as the transport would decode it, marked as a
/// test vault or not. Same root, so the identity gate passes it.
fn replica_of_kind(f: &Fixture, marked: bool) -> keepass_core::model::Vault {
    let mut replica = reopen_kdbx(&f.kdbx_path).vault().clone();
    keys_engine::test_vault::set_marked(&mut replica, marked);
    replica
}

fn assert_marker_mismatch(
    result: Result<keys_engine::ingest::IngestPeerOutcome, EngineError>,
    local: bool,
    replica: bool,
) {
    match result {
        Err(EngineError::TestVaultMarkerMismatch {
            local_is_test,
            replica_is_test,
        }) => assert_eq!((local_is_test, replica_is_test), (local, replica)),
        other => panic!("expected TestVaultMarkerMismatch, got {other:?}"),
    }
}

/// A marked copy of a vault is the same vault (the identity gate passes it)
/// but a different kind: an ordinary mirror refuses it, and a test-vault
/// mirror refuses an unmarked copy, touching nothing either way.
#[test]
fn peer_ingest_refuses_a_test_marker_mismatch_both_ways() {
    let mut f = fixture();
    assert!(!f.engine.is_test_vault().expect("read marker"));
    let marked = replica_of_kind(&f, true);
    let before = mirror_state(&f.engine);
    assert_marker_mismatch(f.engine.ingest_peer("peer-device", &marked), false, true);
    assert_eq!(mirror_state(&f.engine), before);

    let mut f = fixture_of_kind(true);
    assert!(f.engine.is_test_vault().expect("read marker"));
    let unmarked = replica_of_kind(&f, false);
    let before = mirror_state(&f.engine);
    assert_marker_mismatch(f.engine.ingest_peer("peer-device", &unmarked), true, false);
    assert_eq!(mirror_state(&f.engine), before);
}

/// Control: two test-vault replicas of one vault merge normally — the
/// replica's new entry lands — and the marker survives a save + fresh read.
#[test]
fn two_test_vault_replicas_still_merge() {
    let mut f = fixture_of_kind(true);
    let mut replica_file = reopen_kdbx(&f.kdbx_path);
    let root = replica_file.vault().root.id;
    replica_file
        .add_entry(root, NewEntry::new("beta"))
        .expect("replica add");
    let replica = replica_file.vault().clone();
    assert!(keys_engine::test_vault::is_marked(
        &replica.meta.custom_data
    ));

    f.engine
        .ingest_peer("peer-device", &replica)
        .expect("same-kind replicas must merge");
    assert_eq!(
        titles(&f.engine),
        vec!["alpha".to_owned(), "beta".to_owned()]
    );

    let mut template = reopen_kdbx(&f.kdbx_path);
    f.engine
        .save_to_kdbx(&f.kdbx_path, &mut template, None)
        .expect("save");
    let fresh = reopen_kdbx(&f.kdbx_path);
    assert!(keys_engine::test_vault::is_marked(
        &fresh.vault().meta.custom_data
    ));
    assert!(f.engine.is_test_vault().expect("read marker"));
}
