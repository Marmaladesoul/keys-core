//! Integration tests for [`keys_ffi::create_vault`] /
//! [`keys_ffi::create_vault_deterministic`] — the engine-generation vault
//! creation entry points.
//!
//! Creation returns no handle, so every assertion here goes through the
//! same [`keys_ffi::Engine`] open + ingest path a production client uses
//! on the freshly-minted file: that pairing (mint → engine round-trip) is
//! exactly the contract the functions exist to serve.

use std::sync::Arc;

use tempfile::TempDir;

use keys_ffi::{
    Engine, EngineError, VaultDbKeyProvider, VaultDbKeyProviderError, VaultFieldProtector,
    VaultProtectorError, create_vault, create_vault_deterministic,
};

const DB_KEY: [u8; 32] = [0x42; 32];
const SESSION_KEY: [u8; 32] = [0x9c; 32];
const PASSWORD: &str = "test-password";
const CLOCK_MS: i64 = 1_700_000_000_000;

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

fn path_str(dir: &TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().into_owned()
}

/// Open a fresh engine on a sidecar db and ingest the KDBX at
/// `kdbx_path` under `password` (+ optional keyfile) — the production
/// unlock path for a just-created vault.
async fn engine_over(
    dir: &TempDir,
    db_name: &str,
    kdbx_path: &str,
    keyfile: Option<Vec<u8>>,
) -> Result<Arc<Engine>, EngineError> {
    let engine = Engine::open(
        path_str(dir, db_name),
        Arc::new(FixedDbKey),
        Arc::new(FixedProtector),
        None,
    )?;
    engine
        .ingest_from_kdbx_with_keyfile(kdbx_path.to_owned(), PASSWORD.to_owned(), keyfile)
        .await?;
    Ok(engine)
}

#[tokio::test(flavor = "multi_thread")]
async fn create_vault_round_trips_through_engine() {
    let dir = TempDir::new().expect("tempdir");
    let kdbx = path_str(&dir, "fresh.kdbx");

    create_vault(
        kdbx.clone(),
        PASSWORD.to_owned(),
        None,
        "My Vault".to_owned(),
        Some(Arc::new(FixedProtector)),
        None,
    )
    .await
    .expect("create_vault");
    assert!(
        std::path::Path::new(&kdbx).exists(),
        "create_vault must write the file"
    );

    let engine = engine_over(&dir, "fresh.db", &kdbx, None)
        .await
        .expect("engine open + ingest of the fresh vault");
    let groups = engine.group_tree().expect("group_tree");
    assert_eq!(groups.len(), 2, "fresh vault holds exactly root + bin");
    assert!(
        groups.iter().any(|g| g.is_recycle_bin),
        "new vaults ship with the eager recycle-bin group"
    );
    assert!(
        engine.recycle_bin_enabled().expect("recycle_bin_enabled"),
        "new vaults ship with the recycle bin enabled"
    );
    assert_eq!(engine.entry_count(None).expect("entry_count"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_vault_keyfile_fails_closed_without_it() {
    let dir = TempDir::new().expect("tempdir");
    let kdbx = path_str(&dir, "keyed.kdbx");
    let keyfile = keys_ffi::generate_keyfile().expect("mint keyfile");

    create_vault(
        kdbx.clone(),
        PASSWORD.to_owned(),
        Some(keyfile.clone()),
        "Keyed".to_owned(),
        Some(Arc::new(FixedProtector)),
        None,
    )
    .await
    .expect("create_vault with keyfile");

    // Without the keyfile: fail closed at the unlock step. (The ingest
    // path classifies a KDBX-envelope open failure as `Internal` — its
    // `WrongKey` variant is reserved for the SQLite db key — so this
    // asserts the refusal, not the variant.)
    engine_over(&dir, "no-kf.db", &kdbx, None)
        .await
        .expect_err("ingest without the keyfile must fail");

    // With it: opens normally.
    engine_over(&dir, "kf.db", &kdbx, Some(keyfile))
        .await
        .expect("ingest with the keyfile");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_vault_malformed_keyfile_fails_closed_and_writes_nothing() {
    let dir = TempDir::new().expect("tempdir");
    let kdbx = path_str(&dir, "never.kdbx");
    // Looks like an XML keyfile but is structurally broken — must fail
    // closed rather than fall through to a whole-file-hash composite.
    let malformed = b"<?xml version=\"1.0\"?><KeyFile><Key><Data>".to_vec();

    let err = create_vault(
        kdbx.clone(),
        PASSWORD.to_owned(),
        Some(malformed),
        "Never".to_owned(),
        Some(Arc::new(FixedProtector)),
        None,
    )
    .await
    .expect_err("malformed keyfile must fail");
    assert!(
        matches!(err, EngineError::WrongKey),
        "expected WrongKey, got {err:?}"
    );
    assert!(
        !std::path::Path::new(&kdbx).exists(),
        "no weaker vault may be written in place of the failed create"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn create_vault_deterministic_pins_ids_and_composes_with_keyfile() {
    let dir = TempDir::new().expect("tempdir");
    let seed = 42u64;

    // Two same-seed mints, one of them keyfile-keyed: identical id space.
    let plain = path_str(&dir, "a.kdbx");
    create_vault_deterministic(
        plain.clone(),
        PASSWORD.to_owned(),
        None,
        "Det".to_owned(),
        Some(Arc::new(FixedProtector)),
        None,
        seed,
        CLOCK_MS,
    )
    .await
    .expect("deterministic create");

    let keyfile = keys_ffi::generate_keyfile().expect("mint keyfile");
    let keyed = path_str(&dir, "b.kdbx");
    create_vault_deterministic(
        keyed.clone(),
        PASSWORD.to_owned(),
        Some(keyfile.clone()),
        "Det".to_owned(),
        Some(Arc::new(FixedProtector)),
        None,
        seed,
        CLOCK_MS,
    )
    .await
    .expect("deterministic create with keyfile");

    let uuids = |groups: Vec<keys_ffi::GroupNode>| {
        let mut v: Vec<String> = groups.into_iter().map(|g| g.uuid).collect();
        v.sort();
        v
    };
    let a = engine_over(&dir, "a.db", &plain, None)
        .await
        .expect("open plain");
    let b = engine_over(&dir, "b.db", &keyed, Some(keyfile))
        .await
        .expect("open keyed");
    assert_eq!(
        uuids(a.group_tree().expect("tree a")),
        uuids(b.group_tree().expect("tree b")),
        "same seed + clock must pin the same root/bin ids regardless of keyfile"
    );

    // A different seed diverges.
    let other = path_str(&dir, "c.kdbx");
    create_vault_deterministic(
        other.clone(),
        PASSWORD.to_owned(),
        None,
        "Det".to_owned(),
        Some(Arc::new(FixedProtector)),
        None,
        seed + 1,
        CLOCK_MS,
    )
    .await
    .expect("different-seed create");
    let c = engine_over(&dir, "c.db", &other, None)
        .await
        .expect("open other");
    assert_ne!(
        uuids(a.group_tree().expect("tree a")),
        uuids(c.group_tree().expect("tree c")),
        "different seeds must mint different ids"
    );
}
