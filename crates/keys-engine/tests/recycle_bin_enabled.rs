//! Tests for `Meta::recycle_bin_enabled` round-trip via the explicit
//! `setting` row (Phase 2 deferred follow-up).
//!
//! The v1 schema's `is_recycle_bin` column on `group` can only express
//! "enabled" when a bin group exists. `KeePassXC` ships vaults with
//! `enabled=true, recycle_bin_uuid=None` (the bin is created lazily on
//! first soft-delete); without an explicit persistence path that state
//! flips to `enabled=false` on round-trip. Ingest now writes a
//! `meta.recycle_bin_enabled` setting row; projection reads it.

use std::path::Path;
use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewEntry;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use rusqlite::Connection;
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
const COMPOSITE_PW: &[u8] = b"recycle-bin-enabled-tests";
const SETTING_KEY: &str = "meta.recycle_bin_enabled";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(COMPOSITE_PW)
}

fn fresh_kdbx(name: &str) -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), name, Some(protector())).expect("create")
}

fn db_key_hex() -> String {
    let mut s = String::with_capacity(64);
    for b in &DB_KEY_BYTES {
        use std::fmt::Write as _;
        write!(&mut s, "{b:02x}").expect("hex");
    }
    s
}

/// Open the engine's `SQLCipher` file directly to peek at the `setting`
/// table without going through the Engine API.
fn raw_open(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("raw open");
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\"", db_key_hex()))
        .expect("apply key");
    conn
}

fn read_setting_value(conn: &Connection, key: &str) -> Option<Vec<u8>> {
    conn.query_row("SELECT value FROM setting WHERE key = ?1", [key], |row| {
        row.get::<_, Vec<u8>>(0)
    })
    .ok()
}

#[test]
fn ingest_persists_enabled_true_with_no_bin_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");

    // Build a vault with `recycle_bin_enabled = true` but no bin group.
    let mut kdbx = fresh_kdbx("enabled-no-bin");
    let mut vault = kdbx.vault().clone();
    vault.meta.recycle_bin_enabled = true;
    assert!(vault.meta.recycle_bin_uuid.is_none(), "no bin group");
    kdbx.replace_vault(vault);

    let mut engine = Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector(), None)
        .expect("engine open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let conn = raw_open(&engine_path);
    let bytes = read_setting_value(&conn, SETTING_KEY).expect("setting row present");
    assert_eq!(bytes, vec![1u8], "1-byte BLOB encoding TRUE");
}

#[test]
fn ingest_persists_enabled_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");

    let mut kdbx = fresh_kdbx("enabled-false");
    let mut vault = kdbx.vault().clone();
    vault.meta.recycle_bin_enabled = false;
    kdbx.replace_vault(vault);

    let mut engine = Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector(), None)
        .expect("engine open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.close().expect("close");

    let conn = raw_open(&engine_path);
    let bytes = read_setting_value(&conn, SETTING_KEY).expect("setting row present");
    assert_eq!(bytes, vec![0u8], "1-byte BLOB encoding FALSE");
}

#[test]
fn projection_reads_enabled_from_setting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");

    // Start with a vault carrying `enabled=false` (the default) so ingest
    // writes a `false` row, then overwrite via raw connection to `true`.
    let kdbx = fresh_kdbx("setting-direct");
    {
        let mut engine =
            Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        engine.close().expect("close");
    }

    // Overwrite the setting row directly.
    let conn = raw_open(&engine_path);
    conn.execute(
        "INSERT OR REPLACE INTO setting(key, value) VALUES (?1, ?2)",
        rusqlite::params![SETTING_KEY, [1u8].as_slice()],
    )
    .expect("upsert setting");
    drop(conn);

    let engine =
        Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("reopen");
    let vault = engine.project_to_vault().expect("project");
    assert!(
        vault.meta.recycle_bin_enabled,
        "projection should reflect the setting row"
    );
}

#[test]
fn projection_falls_back_when_setting_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");

    // Ingest, then delete the setting row to simulate a legacy DB that
    // predates this fix.
    let kdbx = fresh_kdbx("legacy-fallback");
    {
        let mut engine =
            Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
        engine.ingest_from_kdbx(&kdbx).expect("ingest");
        engine.close().expect("close");
    }
    let conn = raw_open(&engine_path);
    conn.execute(
        "DELETE FROM setting WHERE key = ?1",
        rusqlite::params![SETTING_KEY],
    )
    .expect("delete setting row");
    drop(conn);

    let engine =
        Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("reopen");
    let vault = engine.project_to_vault().expect("project");
    // No bin group exists in this fresh vault, so the fallback says `false`.
    assert!(
        !vault.meta.recycle_bin_enabled,
        "fallback derives from is_recycle_bin column (no bin -> false)"
    );
}

#[test]
fn round_trip_preserves_enabled_true_with_no_bin_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let kdbx_path = dir.path().join("round-trip.kdbx");

    // Source: enabled=true, recycle_bin_uuid=None, plus one entry so
    // the file isn't empty.
    let mut kdbx = fresh_kdbx("enabled-no-bin-roundtrip");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(
        root,
        NewEntry::new("solo").password(SecretString::from("pw")),
    )
    .expect("add entry");
    let mut vault = kdbx.vault().clone();
    vault.meta.recycle_bin_enabled = true;
    kdbx.replace_vault(vault);
    assert!(kdbx.vault().meta.recycle_bin_uuid.is_none());

    // Ingest -> save -> reopen.
    let mut engine = Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector(), None)
        .expect("engine open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    let mut kdbx_mut = kdbx;
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx_mut)
        .expect("save_to_kdbx");
    drop(engine);
    drop(kdbx_mut);

    let reopened = Kdbx::open(&kdbx_path)
        .expect("open")
        .read_header()
        .expect("header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock");
    let reopened_vault = reopened.vault();
    assert!(
        reopened_vault.meta.recycle_bin_enabled,
        "enabled flag preserved across round-trip"
    );
    assert!(
        reopened_vault.meta.recycle_bin_uuid.is_none(),
        "no bin group materialised during round-trip"
    );
}
