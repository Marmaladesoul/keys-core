//! [`Engine::adopt_peer_kdf`]'s write side: the adoption saves over the
//! vault's own file only while that file is still the one the mirror is
//! current with, leaves the mirror settled — in correspondence with the
//! file it wrote, owing it nothing — and changes only the file's KDF
//! settings, never the rest of its envelope (KDBX version, outer cipher). (The approval itself — exact settings,
//! stale approvals refused — is exercised at the FFI seam; see keys-ffi
//! `tests/kdf_approval.rs`.)

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::format::{KdfParams, Version};
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
/// The one KDBX3 envelope in the workspace: keepass-core authors KDBX4
/// only, so a KDBX3 replica borrows this fixture's envelope (see
/// `engine_meta_surface.rs`, which shares it).
const KDBX3_FIXTURE: &str = "../../keyhole/scenarios/fixtures/kdbx3-minimal.kdbx";
/// The fixture's password — a public test credential, not a secret.
const KDBX3_FIXTURE_PW: &[u8] = "tëst pässwörd 🔑/\\".as_bytes();

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

/// `contents` in the KDBX3 fixture's envelope (AES-KDF, KDBX3 cipher and
/// inner stream), re-keyed to [`composite`] — another client's KDBX3 copy of
/// the same vault.
fn in_kdbx3_envelope(contents: &Kdbx<Unlocked>) -> Vec<u8> {
    let mut kdbx3 =
        Kdbx::open(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(KDBX3_FIXTURE))
            .expect("open kdbx3 fixture")
            .read_header()
            .expect("read fixture header")
            .unlock(&CompositeKey::from_password(KDBX3_FIXTURE_PW))
            .expect("unlock kdbx3 fixture");
    kdbx3.replace_vault(contents.vault().clone());
    kdbx3.rekey(&composite()).expect("re-key kdbx3 copy");
    assert_eq!(kdbx3.version(), Version::V3);
    kdbx3.save_to_bytes().expect("kdbx3 bytes")
}

fn header_of(path: &std::path::Path) -> Kdbx<keepass_core::kdbx::HeaderRead> {
    Kdbx::open(path)
        .expect("open kdbx")
        .read_header()
        .expect("read header")
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

#[test]
fn an_adoption_changes_only_the_vault_files_kdf_settings() {
    let mut f = fixture();
    // The peer's copy arrives in a KDBX3 envelope: AES-KDF, and no header
    // HMAC. The user approves its KDF settings, and only those.
    let mut copy = unlock(&f.vault);
    let root = copy.vault().root.id;
    copy.add_entry(root, NewEntry::new("from-kdbx3-peer"))
        .expect("peer entry");
    std::fs::write(&f.peer, in_kdbx3_envelope(&copy)).expect("write peer");
    let peer_header = header_of(&f.peer);
    let approved = KdfCost::of_header(&peer_header).expect("peer cost");
    let before = header_of(&f.vault);
    assert_ne!(KdfCost::of_header(&before).expect("vault cost"), approved);

    f.engine
        .adopt_peer_kdf(&f.peer, &composite(), "peer", &approved, &f.vault, None)
        .expect("adopt");

    let after = header_of(&f.vault);
    assert_eq!(
        KdfCost::of_header(&after).expect("adopted cost"),
        approved,
        "the vault file didn't take the approved KDF settings"
    );
    assert_eq!(
        after.version(),
        Version::V4,
        "the adoption changed the vault file's KDBX version"
    );
    assert_eq!(
        after.header().cipher_id,
        before.header().cipher_id,
        "the adoption changed the vault file's outer cipher"
    );
    assert_eq!(
        f.engine.recorded_kdf_cost().expect("recorded"),
        Some(approved)
    );
    assert_eq!(titles(&f.engine), ["alpha", "from-kdbx3-peer"]);
    // The file the adoption wrote opens, and holds the merge.
    let reopened = unlock(&f.vault);
    let mut on_disk: Vec<_> = reopened
        .vault()
        .iter_entries()
        .map(|e| e.title.clone())
        .collect();
    on_disk.sort();
    assert_eq!(on_disk, ["alpha", "from-kdbx3-peer"]);
}

#[test]
fn an_adoption_refuses_a_kdf_the_vault_files_format_cannot_carry() {
    // The vault's own file is KDBX3; the peer's copy is KDBX4 at Argon2.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("vault.kdbx");
    let peer = dir.path().join("peer.kdbx");
    let mut v4 = Kdbx::create_empty_v4(&composite(), "test").expect("create");
    let root = v4.vault().root.id;
    v4.add_entry(root, NewEntry::new("alpha"))
        .expect("seed entry");
    let kdbx3 = in_kdbx3_envelope(&v4);
    std::fs::write(&vault, &kdbx3).expect("write vault");
    let mut engine = Engine::open(
        &dir.path().join("keys.db"),
        &FixedKey(DB_KEY_BYTES),
        protector(),
        None,
    )
    .expect("open engine");
    let local = unlock(&vault);
    engine.ingest_from_kdbx(&local).expect("ingest");
    engine
        .record_kdbx_state_signature(
            keys_engine::KdbxStateSignature::from_path(&vault).expect("stat"),
        )
        .expect("record signature");

    let mut copy = unlock(&vault);
    let root = copy.vault().root.id;
    copy.add_entry(root, NewEntry::new("from-peer"))
        .expect("peer entry");
    let mut v4_peer = Kdbx::create_empty_v4(&composite(), "test").expect("create peer");
    v4_peer.replace_vault(copy.vault().clone());
    std::fs::write(&peer, v4_peer.save_to_bytes().expect("peer bytes")).expect("write peer");
    let approved = KdfCost::of_header(&header_of(&peer)).expect("peer cost");

    let refused = engine.adopt_peer_kdf(&peer, &composite(), "peer", &approved, &vault, None);

    assert!(
        matches!(&refused, Err(EngineError::Serialise(m)) if m.contains("KDBX3")),
        "{refused:?}"
    );
    assert_eq!(
        titles(&engine),
        ["alpha"],
        "the refused adoption merged the peer"
    );
    assert_eq!(
        std::fs::read(&vault).expect("read vault"),
        kdbx3,
        "the refused adoption wrote the vault file"
    );
}
