//! Integration tests for migration 0002 — non-protected custom fields
//! round-tripping through the `SQLite` mirror.

use std::path::Path;
use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{CustomFieldValue, HistoryPolicy, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::migrations::{self, MIGRATIONS};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use rusqlite::{Connection, params};
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
const COMPOSITE_PW: &[u8] = b"custom-fields-round-trip";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(COMPOSITE_PW)
}

fn fresh_kdbx() -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), "cf-test", Some(protector()))
        .expect("create")
}

fn open_engine(path: &Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

fn vault_with_both_kinds_of_custom_field() -> (Kdbx<Unlocked>, uuid::Uuid) {
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let entry = kdbx
        .add_entry(
            root,
            NewEntry::new("with-custom")
                .username("alice")
                .password(SecretString::from("pw")),
        )
        .expect("add entry");

    kdbx.edit_entry(entry, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "website",
            CustomFieldValue::Plain("example.com".to_string()),
        );
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("secret-token")),
        );
    })
    .expect("edit entry");

    (kdbx, entry.0)
}

#[test]
fn migration_creates_entry_custom_field_table() {
    let mut conn = Connection::open_in_memory().expect("open in-memory");
    migrations::apply_pending(&mut conn).expect("apply migrations");

    let table_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name = 'entry_custom_field'",
            [],
            |r| r.get(0),
        )
        .expect("query sqlite_master");
    assert_eq!(table_count, 1, "entry_custom_field table must exist");

    let index_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'index' AND name = 'idx_entry_custom_field_entry_uuid'",
            [],
            |r| r.get(0),
        )
        .expect("query sqlite_master");
    assert_eq!(index_count, 1, "supporting index must exist");
}

#[test]
fn apply_pending_idempotent_at_latest() {
    let mut conn = Connection::open_in_memory().expect("open in-memory");
    migrations::apply_pending(&mut conn).expect("first apply");
    migrations::apply_pending(&mut conn).expect("second apply no-op");

    let max: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("query schema_version");
    let expected = i64::from(MIGRATIONS.last().expect("at least one migration").version);
    assert_eq!(max, expected, "schema is at latest migration");

    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
        .expect("count schema_version");
    assert_eq!(
        usize::try_from(rows).expect("non-negative"),
        MIGRATIONS.len()
    );
}

#[test]
fn ingest_persists_non_protected_custom_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");

    let (kdbx, entry_uuid) = vault_with_both_kinds_of_custom_field();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    drop(engine);

    let raw = Connection::open(&path).expect("raw open");
    let key_hex: String = DB_KEY_BYTES
        .iter()
        .fold(String::with_capacity(64), |mut acc, b| {
            std::fmt::Write::write_fmt(&mut acc, format_args!("{b:02x}")).expect("write to String");
            acc
        });
    raw.execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\""))
        .expect("apply sqlcipher key");

    let (field_name, value): (String, String) = raw
        .query_row(
            "SELECT field_name, value FROM entry_custom_field WHERE entry_uuid = ?1",
            params![entry_uuid.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("query custom field row");
    assert_eq!(field_name, "website");
    assert_eq!(value, "example.com");

    let np_count: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM entry_custom_field \
             WHERE entry_uuid = ?1 AND field_name = 'Token'",
            params![entry_uuid.to_string()],
            |r| r.get(0),
        )
        .expect("count token");
    assert_eq!(np_count, 0, "protected fields stay in entry_protected");
}

#[test]
fn projection_recovers_non_protected_custom_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");

    let (kdbx, _entry_uuid) = vault_with_both_kinds_of_custom_field();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let mut kdbx = kdbx;
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save_to_kdbx");
    drop(engine);
    drop(kdbx);

    let reopened = Kdbx::open(&kdbx_path)
        .expect("reopen")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock");
    let vault = reopened
        .vault_with_unwrapped_protected()
        .expect("unwrap reopened");

    let entry = vault
        .root
        .entries
        .iter()
        .find(|e| e.title == "with-custom")
        .expect("entry present");

    let website = entry
        .custom_fields
        .iter()
        .find(|cf| cf.key == "website")
        .expect("website field present");
    assert!(
        !website.protected,
        "website should round-trip as non-protected"
    );
    assert_eq!(website.value.as_str(), "example.com");

    let token = entry
        .custom_fields
        .iter()
        .find(|cf| cf.key == "Token")
        .expect("Token field present");
    assert!(token.protected, "Token should round-trip as protected");
    assert_eq!(token.value.as_str(), "secret-token");
}

#[test]
fn entry_full_returns_non_protected_custom_field_refs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");

    let (kdbx, entry_uuid) = vault_with_both_kinds_of_custom_field();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let full = engine
        .entry(entry_uuid)
        .expect("entry call")
        .expect("entry present");

    assert_eq!(full.custom_fields.len(), 2);
    let website = full
        .custom_fields
        .iter()
        .find(|c| c.name == "website")
        .expect("website ref");
    assert!(!website.is_protected);

    let token = full
        .custom_fields
        .iter()
        .find(|c| c.name == "Token")
        .expect("Token ref");
    assert!(token.is_protected);
}

#[test]
fn round_trip_preserves_non_protected_custom_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("round_trip.kdbx");

    let (kdbx, _) = vault_with_both_kinds_of_custom_field();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let mut kdbx = kdbx;
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save_to_kdbx");
    drop(engine);
    drop(kdbx);

    let reopened = Kdbx::open(&kdbx_path)
        .expect("reopen")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock");
    let vault = reopened
        .vault_with_unwrapped_protected()
        .expect("unwrap reopened");

    let entry = vault
        .root
        .entries
        .iter()
        .find(|e| e.title == "with-custom")
        .expect("entry present after reopen");

    let website = entry
        .custom_fields
        .iter()
        .find(|cf| cf.key == "website")
        .expect("website survived reopen");
    assert!(!website.protected);
    assert_eq!(website.value.as_str(), "example.com");
}
