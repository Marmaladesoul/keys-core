//! Integration tests for [`Engine::rekey_to_kdbx`] — the engine half of
//! the vault re-key primitive.
//!
//! Seed a vault under an OLD composite key, ingest it through an
//! `Engine`, re-key + save to a NEW composite key, then reopen from disk
//! and assert the load-bearing trio:
//!
//! 1. the OLD key no longer unlocks the re-keyed file,
//! 2. the NEW key does, and
//! 3. every entry / group / protected field survived the rotation.
//!
//! The save-path machinery (atomic write, recorded signature, mirror as
//! source of truth) is shared with `save_to_kdbx` and proven there; this
//! file pins the parts re-key adds on top.

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
const OLD_PW: &[u8] = b"old-master-pw";
const NEW_PW: &[u8] = b"new-master-pw";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

/// A fresh in-memory KDBX4 vault keyed to the OLD password.
fn fresh_kdbx() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(OLD_PW);
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector())).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

/// Attempt to unlock the file at `path` under `password`. Returns the
/// unlocked handle on success, or the keepass-core error on failure
/// (the honest "does this key open the file?" test).
fn try_open(
    path: &std::path::Path,
    password: &[u8],
) -> Result<Kdbx<Unlocked>, keepass_core::Error> {
    let composite = CompositeKey::from_password(password);
    Kdbx::open(path)
        .expect("open from disk")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite, Some(protector()))
}

/// Seed a vault on disk (via ingest + save under the OLD key) carrying a
/// group with one credential-bearing entry. Returns the temp dir, the
/// kdbx path, and the entry id for later assertions.
fn seed_vault() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    keepass_core::model::EntryId,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let logins = kdbx
        .add_group(root, NewGroup::new("Logins"))
        .expect("add group");
    let entry = kdbx
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
        .expect("seed save under old key");

    (dir, kdbx_path, entry)
}

#[test]
fn rekey_makes_old_key_inert_and_new_key_open() {
    let (dir, kdbx_path, _entry) = seed_vault();
    let db_path = dir.path().join("keys.db");

    // Reopen the engine over the (now-persistent) mirror, open the
    // on-disk file under the OLD key as the envelope template, and
    // rotate to the NEW key.
    let mut engine = open_engine(&db_path);
    let mut kdbx = try_open(&kdbx_path, OLD_PW).expect("old key opens before rekey");
    let new_key = CompositeKey::from_password(NEW_PW);
    engine
        .rekey_to_kdbx(&kdbx_path, &mut kdbx, &new_key, None)
        .expect("rekey_to_kdbx");

    // The load-bearing assertion: the OLD key must NOT open the
    // re-keyed bytes. If rekey silently no-op'd, this would succeed.
    let old_err =
        try_open(&kdbx_path, OLD_PW).expect_err("old key must NOT unlock the re-keyed file");
    // Collapsed crypto failure — we don't distinguish wrong-key from
    // corrupt-payload by design; both are a generic decrypt failure.
    assert!(
        matches!(old_err, keepass_core::Error::Crypto(_)),
        "old key should fail with a crypto error, got {old_err:?}",
    );

    // And the NEW key must open it.
    let _reopened = try_open(&kdbx_path, NEW_PW).expect("new key must unlock the re-keyed file");
}

#[test]
fn rekey_preserves_contents() {
    let (dir, kdbx_path, entry) = seed_vault();
    let db_path = dir.path().join("keys.db");

    let mut engine = open_engine(&db_path);
    let mut kdbx = try_open(&kdbx_path, OLD_PW).expect("old key opens");
    let new_key = CompositeKey::from_password(NEW_PW);
    engine
        .rekey_to_kdbx(&kdbx_path, &mut kdbx, &new_key, None)
        .expect("rekey_to_kdbx");

    // Reopen under the new key and confirm structure + credentials,
    // including the protected password, round-tripped unchanged.
    let reopened = try_open(&kdbx_path, NEW_PW).expect("new key opens");
    let root_group = &reopened.vault().root;
    assert_eq!(root_group.groups.len(), 1, "the Logins group survived");
    let logins = &root_group.groups[0];
    assert_eq!(logins.name, "Logins");
    assert_eq!(logins.entries.len(), 1);
    let entry_back = &logins.entries[0];
    assert_eq!(entry_back.id, entry, "entry id preserved across rekey");
    assert_eq!(entry_back.title, "acme");
    assert_eq!(entry_back.username, "alice");
    assert_eq!(entry_back.url, "https://example.com/");
    let revealed = reopened
        .reveal_password(entry_back.id)
        .expect("reveal protected password");
    assert_eq!(
        revealed, "Tr0ub4dor&3",
        "protected field survives the master-key rotation",
    );
}

#[test]
fn rekey_records_self_write_signature() {
    let (dir, kdbx_path, _entry) = seed_vault();
    let db_path = dir.path().join("keys.db");

    // A freshly reopened engine hasn't written anything yet on this
    // handle, so its self-write signature starts empty.
    let mut engine = open_engine(&db_path);
    assert!(
        engine.last_self_write().is_none(),
        "freshly reopened engine: no self-write yet",
    );

    let mut kdbx = try_open(&kdbx_path, OLD_PW).expect("old key opens");
    let new_key = CompositeKey::from_password(NEW_PW);
    engine
        .rekey_to_kdbx(&kdbx_path, &mut kdbx, &new_key, None)
        .expect("rekey_to_kdbx");

    let sig = engine
        .last_self_write()
        .expect("rekey records a self-write signature like any save");
    let actual_size = std::fs::metadata(&kdbx_path).expect("stat").len();
    assert_eq!(sig.size, actual_size, "signature size matches file size");
}

#[test]
fn rekey_does_not_lose_data_on_io_failure() {
    // A write failure (target parent dir missing) must leave the
    // original file — still keyed to the OLD password — intact, exactly
    // as the plain save path guarantees. A re-key that corrupted the
    // file on a failed write would be a data-loss-and-lockout bug.
    let (dir, kdbx_path, _entry) = seed_vault();
    let db_path = dir.path().join("keys.db");

    let original = std::fs::read(&kdbx_path).expect("read original");

    let mut engine = open_engine(&db_path);
    let mut kdbx = try_open(&kdbx_path, OLD_PW).expect("old key opens");
    let new_key = CompositeKey::from_password(NEW_PW);
    let bad_path = dir.path().join("does-not-exist").join("vault.kdbx");
    let result = engine.rekey_to_kdbx(&bad_path, &mut kdbx, &new_key, None);
    assert!(result.is_err(), "rekey into a missing dir must fail");

    // Original untouched: same bytes, and still opens under the OLD key.
    let after = std::fs::read(&kdbx_path).expect("read after");
    assert_eq!(original, after, "original file untouched on failure");
    let _still_old = try_open(&kdbx_path, OLD_PW)
        .expect("original still opens under the OLD key after a failed rekey");
}
