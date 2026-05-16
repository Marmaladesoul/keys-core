//! Integration tests for the migration framework + initial schema.
//!
//! These exercise [`migrations::apply_pending`] directly against an
//! in-memory `rusqlite::Connection`, and also verify that
//! [`Engine::open`] runs migrations end-to-end against an
//! SQLCipher-encrypted file.

use std::sync::Arc;

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::migrations::{self, MIGRATIONS, MigrationError};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use rusqlite::{Connection, params};

#[derive(Debug)]
struct FixedKey([u8; 32]);

impl KeyProvider for FixedKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.0))
    }
}

#[derive(Debug)]
struct TestProtector([u8; 32]);

impl FieldProtector for TestProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Ok(SessionKey::from_bytes(self.0))
    }
}

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(TestProtector([0x5a; 32]))
}

/// Tables, indices, triggers and the FTS5 virtual table we expect
/// after running every shipped migration.
const EXPECTED_TABLES: &[&str] = &[
    "schema_version",
    "group",
    "entry",
    "entry_protected",
    "entry_custom_field",
    "entry_attachment",
    "entry_history",
    "attachment_blob",
    "tag",
    "entry_tag",
    "smart_folder",
    "setting",
    "entry_fts",
];

const EXPECTED_INDICES: &[&str] = &[
    "idx_group_parent_uuid",
    "idx_entry_group_uuid",
    "idx_entry_url_host",
    "idx_entry_last_used_at",
    "idx_entry_password_strength_bucket",
    "idx_entry_password_fingerprint",
    "idx_entry_attachment_blob_sha256",
    "idx_entry_custom_field_entry_uuid",
    "idx_entry_tag_tag_id",
];

const EXPECTED_TRIGGERS: &[&str] = &["entry_ai", "entry_au", "entry_ad"];

fn object_exists(conn: &Connection, kind: &str, name: &str) -> bool {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |r| r.get(0),
        )
        .expect("query sqlite_master");
    n > 0
}

#[test]
fn apply_pending_on_fresh_db_creates_all_tables() {
    let mut conn = Connection::open_in_memory().expect("open");
    migrations::apply_pending(&mut conn).expect("apply");

    for t in EXPECTED_TABLES {
        assert!(
            object_exists(&conn, "table", t),
            "expected table `{t}` after migrations",
        );
    }
    for i in EXPECTED_INDICES {
        assert!(
            object_exists(&conn, "index", i),
            "expected index `{i}` after migrations",
        );
    }
    for tg in EXPECTED_TRIGGERS {
        assert!(
            object_exists(&conn, "trigger", tg),
            "expected trigger `{tg}` after migrations",
        );
    }
}

#[test]
fn apply_pending_is_idempotent() {
    let mut conn = Connection::open_in_memory().expect("open");
    migrations::apply_pending(&mut conn).expect("first apply");
    migrations::apply_pending(&mut conn).expect("second apply should no-op");
    migrations::apply_pending(&mut conn).expect("third apply still no-op");

    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
        .expect("count");
    assert_eq!(
        usize::try_from(rows).expect("non-negative"),
        MIGRATIONS.len()
    );
}

#[test]
fn apply_pending_rejects_newer_schema() {
    let mut conn = Connection::open_in_memory().expect("open");
    migrations::apply_pending(&mut conn).expect("apply");

    let future = MIGRATIONS.last().unwrap().version + 1;
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        params![future],
    )
    .expect("insert future version");

    let err = migrations::apply_pending(&mut conn).expect_err("must reject");
    match err {
        MigrationError::SchemaTooNew {
            binary_max,
            file_current,
        } => {
            assert_eq!(binary_max, MIGRATIONS.last().unwrap().version);
            assert_eq!(file_current, future);
        }
        other => panic!("expected SchemaTooNew, got {other:?}"),
    }
}

/// Helper: insert a group and an entry. Returns the entry uuid.
fn insert_group_and_entry(conn: &Connection, title: &str) -> (String, String) {
    let gid = "g00000000-0000-0000-0000-000000000001".to_string();
    let eid = "e00000000-0000-0000-0000-000000000001".to_string();
    conn.execute(
        "INSERT INTO \"group\"(uuid, parent_uuid, name, created_at, modified_at) \
         VALUES (?1, NULL, 'Root', 0, 0)",
        params![gid],
    )
    .expect("insert group");
    conn.execute(
        "INSERT INTO entry(uuid, group_uuid, title, created_at, modified_at, accessed_at) \
         VALUES (?1, ?2, ?3, 0, 0, 0)",
        params![eid, gid, title],
    )
    .expect("insert entry");
    (gid, eid)
}

fn fts_match_count(conn: &Connection, query: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM entry_fts WHERE entry_fts MATCH ?1",
        params![query],
        |r| r.get(0),
    )
    .expect("fts match query")
}

#[test]
fn fts5_trigger_keeps_index_synced() {
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON")
        .expect("fks on");
    migrations::apply_pending(&mut conn).expect("apply");

    let (_gid, eid) = insert_group_and_entry(&conn, "banking site");

    assert_eq!(fts_match_count(&conn, "banking"), 1, "after insert");
    assert_eq!(fts_match_count(&conn, "media"), 0, "no media yet");

    conn.execute(
        "UPDATE entry SET title = 'media site' WHERE uuid = ?1",
        params![eid],
    )
    .expect("update");

    assert_eq!(fts_match_count(&conn, "banking"), 0, "banking gone");
    assert_eq!(fts_match_count(&conn, "media"), 1, "media present");

    conn.execute("DELETE FROM entry WHERE uuid = ?1", params![eid])
        .expect("delete");

    assert_eq!(
        fts_match_count(&conn, "banking"),
        0,
        "all gone after delete"
    );
    assert_eq!(fts_match_count(&conn, "media"), 0, "all gone after delete");
}

#[test]
fn foreign_keys_enforced_when_pragma_on() {
    let mut conn = Connection::open_in_memory().expect("open");
    conn.execute_batch("PRAGMA foreign_keys = ON")
        .expect("fks on");
    migrations::apply_pending(&mut conn).expect("apply");

    // No groups exist. Insert an entry pointing at a missing group.
    let err = conn
        .execute(
            "INSERT INTO entry(uuid, group_uuid, created_at, modified_at, accessed_at) \
             VALUES ('e1', 'no-such-group', 0, 0, 0)",
            [],
        )
        .expect_err("FK violation expected");

    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("foreign key"),
        "expected FK violation error, got {msg}",
    );
}

#[test]
fn engine_open_applies_migrations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key = FixedKey([0x33; 32]);

    let engine = Engine::open(&path, &key, protector()).expect("open fresh");
    engine.close().expect("close");

    // Reopen and verify the schema is present via a direct rusqlite
    // peek. We use rusqlite directly here because the engine's query
    // API doesn't exist yet (Phase 1.5+); the underlying SQLCipher
    // file is the same shape either way.
    let raw = Connection::open(&path).expect("raw open");
    raw.execute_batch(
        "PRAGMA key = \"x'3333333333333333333333333333333333333333333333333333333333333333'\"",
    )
    .expect("apply key");

    for t in EXPECTED_TABLES {
        assert!(
            object_exists(&raw, "table", t),
            "expected table `{t}` after Engine::open",
        );
    }

    let v: i64 = raw
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("query schema_version");
    assert_eq!(
        u32::try_from(v).expect("non-negative"),
        MIGRATIONS.last().unwrap().version,
    );
}

#[test]
fn engine_open_idempotent_on_existing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key = FixedKey([0x77; 32]);

    Engine::open(&path, &key, protector())
        .expect("first")
        .close()
        .unwrap();
    Engine::open(&path, &key, protector())
        .expect("second")
        .close()
        .unwrap();
    Engine::open(&path, &key, protector())
        .expect("third")
        .close()
        .unwrap();

    let raw = Connection::open(&path).expect("raw open");
    raw.execute_batch(
        "PRAGMA key = \"x'7777777777777777777777777777777777777777777777777777777777777777'\"",
    )
    .expect("apply key");

    let rows: i64 = raw
        .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
        .expect("query");
    assert_eq!(
        usize::try_from(rows).expect("non-negative"),
        MIGRATIONS.len(),
        "no duplicate migration rows",
    );
}
