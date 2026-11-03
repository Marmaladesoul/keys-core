//! [`Engine::adopt_peer_kdf`]'s write side: the adoption saves over the
//! vault's own file only while that file is still the one the mirror is
//! current with, and leaves the mirror settled — in correspondence with the
//! file it wrote, owing it nothing. (The approval itself — exact settings,
//! stale approvals refused — is exercised at the FFI seam; see keys-ffi
//! `tests/kdf_approval.rs`.)

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::format::KdfParams;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewEntry;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, EngineError, KdfCost, KeyProvider, KeyProviderError, Pagination};

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
/// Argon2 memory of the peer's re-keyed copy: not the vault's own.
const PEER_MEMORY_BYTES: u64 = 8 * 1024 * 1024;

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(PASSWORD)
}

fn unlock(path: &std::path::Path) -> Kdbx<Unlocked> {
    Kdbx::open(path)
        .expect("open kdbx")
        .read_header()
        .expect("read header")
        .unlock(&composite())
        .expect("unlock kdbx")
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

struct Fixture {
    _dir: tempfile::TempDir,
    vault: std::path::PathBuf,
    peer: std::path::PathBuf,
    engine: Engine,
    /// The cost of the peer copy's KDF settings — what the user approved.
    approved: KdfCost,
}

/// A mirror saved to `vault.kdbx`, and a peer's copy of the same vault at
/// `peer.kdbx`, re-keyed to other Argon2 memory and carrying an entry the
/// mirror lacks.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("vault.kdbx");
    let peer = dir.path().join("peer.kdbx");
    let mut kdbx = Kdbx::create_empty_v4_with_protector(&composite(), "test", Some(protector()))
        .expect("create");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("alpha"))
        .expect("seed entry");
    let mut engine = Engine::open(
        &dir.path().join("keys.db"),
        &FixedKey(DB_KEY_BYTES),
        protector(),
        None,
    )
    .expect("open engine");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&vault, &mut kdbx, None)
        .expect("initial save");

    let mut copy = unlock(&vault);
    let root = copy.vault().root.id;
    copy.add_entry(root, NewEntry::new("from-peer"))
        .expect("peer entry");
    let mut params = copy.outer_header().decode_kdf_params().expect("kdf params");
    let KdfParams::Argon2 { memory_bytes, .. } = &mut params else {
        panic!("fixture vault is Argon2");
    };
    *memory_bytes = PEER_MEMORY_BYTES;
    copy.rekey_with_kdf(&composite(), &params)
        .expect("re-key peer copy");
    std::fs::write(&peer, copy.save_to_bytes().expect("peer bytes")).expect("write peer");

    Fixture {
        _dir: dir,
        vault,
        peer,
        engine,
        approved: KdfCost::of(&params),
    }
}

#[test]
fn an_adoption_leaves_the_mirror_owing_its_file_nothing() {
    let mut f = fixture();
    f.engine
        .adopt_peer_kdf(&f.peer, &composite(), "peer", &f.approved, &f.vault, None)
        .expect("adopt");

    assert_eq!(titles(&f.engine), ["alpha", "from-peer"]);
    assert_eq!(
        f.engine.recorded_kdf_cost().expect("recorded"),
        Some(f.approved.clone())
    );
    assert!(
        !f.engine.persistence_state().expect("state").is_dirty(),
        "the adoption left the mirror owing the file it just wrote"
    );
}

#[test]
fn an_adoption_refuses_a_vault_file_that_changed_under_it() {
    let mut f = fixture();
    // Another writer replaces the vault's file after the mirror was last
    // brought current with it.
    let mut other = unlock(&f.vault);
    let root = other.vault().root.id;
    other
        .add_entry(root, NewEntry::new("external"))
        .expect("external entry");
    let changed = other.save_to_bytes().expect("external bytes");
    std::fs::write(&f.vault, &changed).expect("external write");

    let refused =
        f.engine
            .adopt_peer_kdf(&f.peer, &composite(), "peer", &f.approved, &f.vault, None);

    assert!(
        matches!(refused, Err(EngineError::VaultFileChanged)),
        "{refused:?}"
    );
    assert_eq!(
        titles(&f.engine),
        ["alpha"],
        "the refused adoption merged the peer"
    );
    assert_eq!(
        std::fs::read(&f.vault).expect("read vault"),
        changed,
        "the refused adoption wrote over the changed file"
    );
}
