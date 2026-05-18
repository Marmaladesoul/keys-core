//! Integration tests for [`Engine::last_saved_kdbx_bytes`] (task 4.4).
//!
//! Covers: returns `None` before any save; populated after save; matches
//! on-disk bytes byte-for-byte; overwritten on subsequent save; survives
//! engine close + reopen; the stored bytes re-parse successfully through
//! [`keepass_core::kdbx::Kdbx::open`] (proving they're a valid common
//! ancestor for the upcoming 4.6 3-way merge). Plus an `#[ignore]`-d
//! large-vault size + timing smoke.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{NewEntry, NewGroup};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use secrecy::SecretString;

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
const COMPOSITE_PW: &[u8] = b"pw";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(COMPOSITE_PW);
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector())).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

/// Re-open KDBX bytes through `keepass-core` and unlock. Proves the
/// stored common-ancestor bytes are a valid KDBX, ready to feed into
/// the task 4.6 3-way merge.
fn unlock_bytes(bytes: &[u8]) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(COMPOSITE_PW);
    Kdbx::open_from_bytes(bytes.to_vec())
        .expect("open_from_bytes")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite, Some(protector()))
        .expect("unlock")
}

#[test]
fn last_saved_kdbx_bytes_is_none_before_any_save() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let engine = open_engine(&db_path);

    assert!(
        engine.last_saved_kdbx_bytes().expect("query").is_none(),
        "no row before any save",
    );
}

#[test]
fn save_persists_last_saved_kdbx_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save_to_kdbx");

    let stored = engine
        .last_saved_kdbx_bytes()
        .expect("query")
        .expect("row present after save");
    let on_disk = std::fs::read(&kdbx_path).expect("read kdbx file");

    assert_eq!(
        stored, on_disk,
        "stored common-ancestor bytes must match what landed on disk",
    );
}

#[test]
fn subsequent_save_overwrites_last_saved_kdbx_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("first save");
    let first = engine
        .last_saved_kdbx_bytes()
        .expect("q1")
        .expect("first save populated row");

    // Mutate: add a group + entry through keepass-core, re-ingest so
    // SQLite picks up the change, then save again. KDBX4 also rolls a
    // fresh random IV per save, so even an identical vault would
    // serialise to different bytes — but a content delta makes the
    // round-trip self-evidently different.
    let root = kdbx.vault().root.id;
    let folder = kdbx
        .add_group(root, NewGroup::new("Logins"))
        .expect("add group");
    kdbx.add_entry(folder, NewEntry::new("delta"))
        .expect("add entry");
    engine.ingest_from_kdbx(&kdbx).expect("re-ingest");

    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("second save");
    let second = engine
        .last_saved_kdbx_bytes()
        .expect("q2")
        .expect("second save populated row");
    let on_disk = std::fs::read(&kdbx_path).expect("read kdbx file");

    assert_ne!(first, second, "row overwritten on second save");
    assert_eq!(second, on_disk, "row matches latest on-disk bytes");
}

#[test]
fn last_saved_kdbx_bytes_survives_engine_close_and_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let saved_bytes = {
        let mut kdbx = fresh_kdbx();
        let mut engine = open_engine(&db_path);
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        engine
            .save_to_kdbx(&kdbx_path, &mut kdbx, None)
            .expect("save_to_kdbx");
        let bytes = engine
            .last_saved_kdbx_bytes()
            .expect("query")
            .expect("row present");
        engine.close().expect("close");
        bytes
    };

    // Reopen the same SQLCipher file under the same key and read back
    // the setting row — proves persistence beyond the in-process handle.
    let engine = open_engine(&db_path);
    let reloaded = engine
        .last_saved_kdbx_bytes()
        .expect("query after reopen")
        .expect("row survives reopen");

    assert_eq!(
        saved_bytes, reloaded,
        "common-ancestor bytes survive engine close + reopen",
    );
}

#[test]
fn last_saved_kdbx_bytes_decodes_via_keepass_core() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    // Seed a vault with a known entry so we can prove the re-parsed
    // bytes carry the same content.
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let logins = kdbx
        .add_group(root, NewGroup::new("Logins"))
        .expect("add group");
    let entry_id = kdbx
        .add_entry(
            logins,
            NewEntry::new("acme")
                .username("alice")
                .url("https://example.com/")
                .password(SecretString::from("Tr0ub4dor&3")),
        )
        .expect("add entry");

    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save_to_kdbx");

    let stored = engine
        .last_saved_kdbx_bytes()
        .expect("query")
        .expect("row present");

    // The headline assertion: the stored bytes round-trip through the
    // keepass-core open path, just like 4.6 will use them.
    let reparsed = unlock_bytes(&stored);
    let root_back = &reparsed.vault().root;
    assert_eq!(root_back.groups.len(), 1, "single child group");
    let logins_back = &root_back.groups[0];
    assert_eq!(logins_back.name, "Logins");
    assert_eq!(logins_back.entries.len(), 1);
    let entry_back = &logins_back.entries[0];
    assert_eq!(entry_back.id, entry_id);
    assert_eq!(entry_back.title, "acme");
    assert_eq!(entry_back.username, "alice");
    assert_eq!(entry_back.url, "https://example.com/");
    let revealed = reparsed.reveal_password(entry_back.id).expect("reveal");
    assert_eq!(revealed, "Tr0ub4dor&3");
}

/// `#[ignore]`-d perf-flavoured smoke: an 877-entry vault round-trips
/// through the `setting` BLOB unscathed. Logs the byte size + total
/// save time so the PR can record a reference number.
#[test]
#[ignore = "slow; run with `cargo test --release -- --ignored`"]
fn large_vault_round_trips_through_setting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    for i in 0..877 {
        kdbx.add_entry(
            root,
            NewEntry::new(format!("entry-{i}"))
                .username(format!("user-{i}"))
                .password(SecretString::from(format!("p4ssw0rd-{i:04}!"))),
        )
        .expect("add entry");
    }

    let mut engine = open_engine(&db_path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let started = std::time::Instant::now();
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save_to_kdbx");
    eprintln!("877-entry save_to_kdbx took {:?}", started.elapsed());

    let stored = engine
        .last_saved_kdbx_bytes()
        .expect("query")
        .expect("row present");
    let on_disk = std::fs::read(&kdbx_path).expect("read file");

    eprintln!(
        "877-entry common-ancestor blob size: {} bytes",
        stored.len()
    );
    assert_eq!(stored.len(), on_disk.len(), "BLOB column did not truncate");
    assert_eq!(stored, on_disk, "bytes match on-disk file");

    // Round-trip through keepass-core too — proves the large blob is
    // still a valid KDBX after the setting-table detour.
    let reparsed = unlock_bytes(&stored);
    assert_eq!(
        reparsed.vault().root.entries.len(),
        877,
        "all entries survive the BLOB round-trip",
    );
}
