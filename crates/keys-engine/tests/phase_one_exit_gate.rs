//! Phase 1 exit-gate integration test.
//!
//! Proves the full open → migrate → key-handshake → close → reopen loop
//! holds end-to-end against an SQLCipher-encrypted file on disk, with a
//! random 32-byte key, before Phase 2 starts wiring real ingest paths.
//!
//! See `_localdocs/SQLITE_MIGRATION.md` task 1.6 and the Phase 1 exit
//! gate description.

use std::fmt::Write as _;

use std::sync::Arc;

use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::migrations::MIGRATIONS;
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use rand::RngCore;
use rusqlite::{Connection, params};

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

/// Test-only `KeyProvider` that hands out a fixed 32-byte key.
///
/// Mirrors the same idiom used in `tests/migrations.rs` but with a
/// freshly-generated random key per test invocation rather than a
/// hard-coded byte pattern — this is the bit the exit-gate explicitly
/// calls out ("open empty DB under a random 32-byte key").
#[derive(Debug)]
struct FixedKeyProvider([u8; 32]);

impl KeyProvider for FixedKeyProvider {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.0))
    }
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

/// Format a 32-byte key as the `x'…hex…'` literal `SQLCipher` wants on
/// the raw PRAGMA path. We need a raw `rusqlite::Connection` for the
/// direct inserts and reads because the engine's query API is still a
/// Phase 1.5 stub — same shortcut `tests/migrations.rs` takes.
fn pragma_key_literal(key: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(2 * key.len());
    for b in key {
        write!(&mut hex, "{b:02x}").expect("write hex");
    }
    format!("PRAGMA key = \"x'{hex}'\"")
}

fn open_raw_with_key(path: &std::path::Path, key: &[u8; 32]) -> Connection {
    let conn = Connection::open(path).expect("raw open");
    conn.execute_batch(&pragma_key_literal(key))
        .expect("apply key");
    conn
}

#[test]
fn phase_one_exit_gate_full_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");

    let key_bytes = random_key();
    let provider = FixedKeyProvider(key_bytes);

    // 1. Open fresh — file does not exist yet. Migrations run.
    let engine = Engine::open(&path, &provider, protector(), None).expect("open fresh");

    // 2. Sanity-check the schema version got bumped to MIGRATIONS' max.
    //    We can't see inside the engine, so close + peek via raw conn.
    engine.close().expect("close after fresh open");

    {
        let raw = open_raw_with_key(&path, &key_bytes);
        let v: i64 = raw
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .expect("query schema_version");
        assert_eq!(
            u32::try_from(v).expect("non-negative version"),
            MIGRATIONS.last().unwrap().version,
            "schema_version should equal the max shipped migration",
        );

        // 3. Insert a root group directly. `group` is a reserved word —
        //    quote it. Timestamps are Unix ms per schema.md; for the
        //    purposes of this exit-gate test any non-negative integer
        //    is fine.
        let gid = "g00000000-0000-0000-0000-000000000001";
        raw.execute(
            "INSERT INTO \"group\"(uuid, parent_uuid, name, created_at, modified_at) \
             VALUES (?1, NULL, ?2, 0, 0)",
            params![gid, "Root"],
        )
        .expect("insert group");
        // Connection drops here, closing the raw handle.
    }

    // 4. Reopen with the SAME key. Must succeed (no WrongKey).
    let engine = Engine::open(&path, &provider, protector(), None).expect("reopen with same key");
    engine.close().expect("close after reopen");

    // 5. Final raw peek — confirm the row we wrote survived the
    //    close/reopen cycle and the encrypted page state is coherent.
    let raw = open_raw_with_key(&path, &key_bytes);
    let name: String = raw
        .query_row(
            "SELECT name FROM \"group\" WHERE uuid = ?1",
            params!["g00000000-0000-0000-0000-000000000001"],
            |r| r.get(0),
        )
        .expect("select group back");
    assert_eq!(
        name, "Root",
        "group name round-tripped through close/reopen"
    );
}

#[test]
fn phase_one_exit_gate_full_lifecycle_with_search() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");

    let key_bytes = random_key();
    let provider = FixedKeyProvider(key_bytes);

    // Fresh open + migrations.
    Engine::open(&path, &provider, protector(), None)
        .expect("open fresh")
        .close()
        .expect("close after fresh open");

    let gid = "00000000-0000-0000-0000-0000000000aa";
    let eid = "00000000-0000-0000-0000-0000000000bb";

    // Insert a group + an entry directly via SQLCipher.
    {
        let raw = open_raw_with_key(&path, &key_bytes);
        raw.execute(
            "INSERT INTO \"group\"(uuid, parent_uuid, name, created_at, modified_at) \
             VALUES (?1, NULL, 'Root', 0, 0)",
            params![gid],
        )
        .expect("insert group");
        raw.execute(
            "INSERT INTO entry(uuid, group_uuid, title, created_at, modified_at, accessed_at) \
             VALUES (?1, ?2, ?3, 0, 0, 0)",
            params![eid, gid, "banking site"],
        )
        .expect("insert entry");
    }

    // Reopen the engine, then verify search finds the entry — proving
    // migrations + storage stay coherent across close/reopen.
    let engine = Engine::open(&path, &provider, protector(), None).expect("reopen with same key");
    let hits = engine
        .search(
            "banking",
            keys_engine::SearchScope::AnyField,
            keys_engine::Pagination::all(),
        )
        .expect("search");
    assert_eq!(hits.len(), 1, "search hits survived close/reopen");
    assert_eq!(hits[0].title, "banking site");
    engine.close().expect("close after reopen");
}
