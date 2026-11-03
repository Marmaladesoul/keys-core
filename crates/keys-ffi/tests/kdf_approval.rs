//! KDF approval as the FFI surfaces it: a derive of the vault's own file is
//! held to the KDF settings the mirror recorded for it — or, with none
//! recorded, to this process's ceiling — and anything else is
//! [`EngineError::KdfApprovalRequired`] until the call is repeated with
//! exactly the file's settings (`read_kdbx_kdf`) as `approved_kdf`; a peer
//! whose settings changed merges only through `adopt_peer_kdbx`, at exactly
//! the settings approved, and the vault then carries them.
//!
//! The changed files are real re-keys under the same password
//! (`Kdbx::rekey_with_kdf`), as another client would write. Costs are kept
//! cheap; the hostile-cost shapes are the keyhole scenario
//! `kdf-approval.sh`, under a watchdog.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::format::KdfParams;
use keepass_core::kdbx::Kdbx;
use keepass_core::model::NewEntry;
use keys_ffi::{
    Engine, EngineEntryUpdate, EngineError, KdfCeilingProfile, KdfSettings, Page, SyncWithDiskFfi,
    VaultDbKeyProvider, VaultDbKeyProviderError, VaultFieldProtector, VaultProtectorError,
    read_kdbx_kdf, set_kdf_ceiling,
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

/// The seeded entry's password, before any edit.
const ALPHA_PASSWORD: &str = "alpha-before";

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
    kdbx.add_entry(
        root,
        NewEntry::new("alpha").password(secrecy::SecretString::from(ALPHA_PASSWORD)),
    )
    .expect("add entry");
    std::fs::write(&kdbx_path, kdbx.save_to_bytes().expect("save bytes")).expect("write vault");
    let engine = open_fresh_engine(&dir.join("keys.db"));
    let first = engine
        .sync_with_disk(
            path_string(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            None,
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

/// Re-key the vault file at `path` under the same password with its Argon2
/// memory set to `memory_mib` and passes to `iterations`, adding an entry
/// titled `title` if given — another client changing the KDF settings.
fn set_kdf(path: &std::path::Path, memory_mib: u64, iterations: u64, title: Option<&str>) {
    let mut kdbx = Kdbx::open(path)
        .expect("open")
        .read_header()
        .expect("header")
        .unlock(&composite())
        .expect("unlock");
    if let Some(title) = title {
        let root = kdbx.vault().root.id;
        kdbx.add_entry(root, NewEntry::new(title))
            .expect("add entry");
    }
    let mut params = kdbx.outer_header().decode_kdf_params().expect("kdf params");
    let KdfParams::Argon2 {
        memory_bytes,
        iterations: passes,
        ..
    } = &mut params
    else {
        panic!("expected an Argon2 vault");
    };
    *memory_bytes = memory_mib << 20;
    *passes = iterations;
    kdbx.rekey_with_kdf(&composite(), &params)
        .expect("rekey with kdf");
    std::fs::write(path, kdbx.save_to_bytes().expect("save")).expect("write");
}

fn settings_of(path: &std::path::Path) -> KdfSettings {
    read_kdbx_kdf(path_string(path)).expect("read kdf").settings
}

fn needs_approval(r: Result<impl std::fmt::Debug, EngineError>) -> bool {
    r.is_err_and(|e| matches!(e, EngineError::KdfApprovalRequired { .. }))
}

#[tokio::test]
async fn a_changed_vault_file_is_derived_only_at_the_approved_settings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, kdbx_path) = bound_engine(dir.path()).await;
    let recorded = engine.recorded_kdf().expect("recorded").expect("some");
    assert_eq!(recorded.settings, settings_of(&kdbx_path));

    set_kdf(&kdbx_path, 32, 3, Some("beta"));
    let bytes = std::fs::read(&kdbx_path).expect("read");
    let before = seam_state(&engine);
    let changed = read_kdbx_kdf(path_string(&kdbx_path)).expect("read kdf");
    assert_ne!(changed.settings, recorded.settings);

    // Refused from the header, by the reconcile and by a save alike.
    assert!(needs_approval(
        engine
            .reconcile_with_disk_park_conflicts_with_keyfile(
                path_string(&kdbx_path),
                KDBX_PASSWORD.to_owned(),
                None,
                None,
            )
            .await
    ));
    assert!(needs_approval(
        engine
            .save_to_kdbx(path_string(&kdbx_path), KDBX_PASSWORD.to_owned(), None)
            .await
    ));
    // An approval for other settings covers nothing.
    assert!(needs_approval(
        engine
            .sync_with_disk(
                path_string(&kdbx_path),
                KDBX_PASSWORD.to_owned(),
                None,
                None,
                Some(recorded.settings.clone()),
            )
            .await
    ));
    assert_eq!(seam_state(&engine), before, "a refusal changed the mirror");
    assert_eq!(
        std::fs::read(&kdbx_path).expect("read"),
        bytes,
        "a refusal wrote the file"
    );

    // The exact settings shown go through, and become the vault's.
    engine
        .sync_with_disk(
            path_string(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            None,
            None,
            Some(changed.settings.clone()),
        )
        .await
        .expect("approved sync");
    assert_eq!(titles(&engine), ["alpha", "beta"]);
    assert_eq!(
        engine
            .recorded_kdf()
            .expect("recorded")
            .expect("some")
            .settings,
        changed.settings
    );
    assert!(
        !engine.persistence_state().expect("state").is_dirty,
        "adopting the file's settings left the mirror owing it a write"
    );
    engine
        .save_to_kdbx(path_string(&kdbx_path), KDBX_PASSWORD.to_owned(), None)
        .await
        .expect("a save at the recorded settings needs no approval");
}

#[tokio::test]
async fn a_first_open_past_the_ceiling_needs_approval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_bound, kdbx_path) = bound_engine(dir.path()).await;
    // Past the memory-constrained ceiling (64 MiB), within the standard one.
    set_kdf(&kdbx_path, 96, 1, None);
    let big = read_kdbx_kdf(path_string(&kdbx_path)).expect("read kdf");
    assert!(!big.exceeds_ceiling);

    set_kdf_ceiling(KdfCeilingProfile::MemoryConstrained);
    let summary = read_kdbx_kdf(path_string(&kdbx_path)).expect("read kdf");
    let fresh = open_fresh_engine(&dir.path().join("fresh.db"));
    let refused = fresh
        .ingest_from_kdbx_with_keyfile(
            path_string(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            None,
            None,
        )
        .await;
    let approved = fresh
        .ingest_from_kdbx_with_keyfile(
            path_string(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            None,
            Some(summary.settings.clone()),
        )
        .await;
    set_kdf_ceiling(KdfCeilingProfile::Standard);

    assert!(summary.exceeds_ceiling);
    assert!(needs_approval(refused));
    approved.expect("the approved first open");
    assert_eq!(titles(&fresh), ["alpha"]);
}

/// Change the password of the entry titled `title` in the mirror, unsaved.
fn set_password(engine: &Engine, title: &str, password: &str) {
    let uuid = engine
        .list_entries(
            None,
            Page {
                offset: 0,
                limit: 100,
            },
        )
        .expect("list")
        .into_iter()
        .find(|e| e.title == title)
        .expect("entry")
        .uuid;
    engine
        .update_entry(
            uuid,
            EngineEntryUpdate {
                password: Some(password.to_owned()),
                ..Default::default()
            },
        )
        .expect("local edit");
}

/// The password of the entry titled `title` in the vault file itself.
fn password_on_disk(path: &std::path::Path, title: &str) -> String {
    let kdbx = Kdbx::open(path)
        .expect("open")
        .read_header()
        .expect("header")
        .unlock(&composite())
        .expect("unlock");
    kdbx.vault()
        .iter_entries()
        .find(|e| e.title == title)
        .expect("entry on disk")
        .password
        .clone()
}

#[tokio::test]
async fn an_approved_peer_rekey_is_adopted_and_a_stale_approval_is_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, kdbx_path) = bound_engine(dir.path()).await;
    let peer = dir.path().join("peer.kdbx");
    std::fs::copy(&kdbx_path, &peer).expect("copy");
    set_kdf(&peer, 32, 3, Some("from-peer"));
    let peer_settings = settings_of(&peer);
    // A local edit the peer doesn't have, not yet saved: the adoption's
    // save must write it, not the peer's older value.
    set_password(&engine, "alpha", "alpha-after");

    assert!(matches!(
        engine
            .ingest_peer_kdbx(
                "peer".to_owned(),
                path_string(&peer),
                KDBX_PASSWORD.to_owned(),
                None,
            )
            .await,
        Err(EngineError::KdfParametersMismatch { .. })
    ));

    engine
        .adopt_peer_kdbx(
            "peer".to_owned(),
            path_string(&peer),
            path_string(&kdbx_path),
            KDBX_PASSWORD.to_owned(),
            None,
            peer_settings.clone(),
            None,
        )
        .await
        .expect("adopt");
    assert_eq!(titles(&engine), ["alpha", "from-peer"]);
    assert_eq!(
        password_on_disk(&kdbx_path, "alpha"),
        "alpha-after",
        "the adoption wrote the peer's value over a local edit"
    );
    assert_eq!(
        settings_of(&kdbx_path),
        peer_settings,
        "the vault file didn't take the peer's settings"
    );
    assert_eq!(
        engine
            .recorded_kdf()
            .expect("recorded")
            .expect("some")
            .settings,
        peer_settings
    );
    // The adopted file is in correspondence with the mirror.
    assert!(matches!(
        engine
            .sync_with_disk(
                path_string(&kdbx_path),
                KDBX_PASSWORD.to_owned(),
                None,
                None,
                None
            )
            .await
            .expect("sync"),
        SyncWithDiskFfi::UpToDate
    ));

    // The peer changes its settings again: the earlier approval is stale.
    set_kdf(&peer, 32, 4, Some("later"));
    let bytes = std::fs::read(&kdbx_path).expect("read");
    let before = seam_state(&engine);
    assert!(matches!(
        engine
            .adopt_peer_kdbx(
                "peer".to_owned(),
                path_string(&peer),
                path_string(&kdbx_path),
                KDBX_PASSWORD.to_owned(),
                None,
                peer_settings,
                None,
            )
            .await,
        Err(EngineError::KdfParametersMismatch { .. })
    ));
    assert_eq!(seam_state(&engine), before);
    assert_eq!(std::fs::read(&kdbx_path).expect("read"), bytes);
}
