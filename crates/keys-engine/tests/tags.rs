//! Integration tests for `Engine::list_tags` (Phase 6.13 prep) and
//! the in-transaction tag GC that keeps the `tag` table clean.
//!
//! Covers the vault-wide tag-list read path that replaces the Swift
//! `TagListStore`, plus the GC sweep wired into every mutation that
//! can orphan a tag row (`set_tags`, `delete_entry`, `delete_group`).

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, Engine, IconRef, KeyProvider, KeyProviderError, NewEntryFields, NewGroupFields,
};
use rusqlite::Connection;
use secrecy::SecretString;
use uuid::Uuid;

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

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn fresh_kdbx(protector: Arc<dyn FieldProtector>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector)).expect("create")
}

fn engine_with_empty_vault() -> (Engine, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx(protector());
    let root_uuid = kdbx.vault().root.id.0;
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (engine, root_uuid, dir)
}

fn new_group(name: &str) -> NewGroupFields {
    NewGroupFields {
        name: name.into(),
        notes: String::new(),
        icon: IconRef::Builtin(0),
    }
}

/// Open a raw sqlcipher connection to the engine's db file, applying
/// the same PRAGMA key the engine uses. Lets tests inspect the `tag`
/// table directly to assert the GC actually ran (rather than just
/// observing the `list_tags` projection).
fn raw_open(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).expect("raw open");
    let mut hex = String::with_capacity(64);
    for b in &DB_KEY_BYTES {
        use std::fmt::Write as _;
        write!(&mut hex, "{b:02x}").expect("hex");
    }
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\""))
        .expect("apply key");
    conn
}

fn raw_tag_names(db_path: &std::path::Path) -> Vec<String> {
    let conn = raw_open(db_path);
    let mut stmt = conn
        .prepare("SELECT name FROM tag ORDER BY name ASC")
        .expect("prepare");
    stmt.query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect")
}

fn new_entry(title: &str, tags: Vec<String>) -> NewEntryFields {
    NewEntryFields {
        title: title.into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: SecretString::from("p"),
        icon: IconRef::Builtin(0),
        custom_fields: Vec::new(),
        tags,
    }
}

#[test]
fn list_tags_returns_empty_for_no_tagged_entries() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    // An entry with no tags shouldn't surface anything.
    engine
        .create_entry(root, new_entry("untagged", Vec::new()))
        .expect("create");
    let tags = engine.list_tags().expect("list_tags");
    assert!(tags.is_empty(), "expected no tags, got {tags:?}");
}

#[test]
fn list_tags_returns_sorted_unique_tags() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    // Insert in non-alphabetical order, with a duplicate within the
    // same entry — `insert_tags` dedupes, but we also want to be sure
    // the read side returns a stable, sorted list.
    engine
        .create_entry(
            root,
            new_entry("e1", vec!["banana".into(), "apple".into(), "banana".into()]),
        )
        .expect("create");
    let tags = engine.list_tags().expect("list_tags");
    assert_eq!(tags, vec!["apple".to_owned(), "banana".to_owned()]);
}

#[test]
fn list_tags_includes_tags_from_multiple_entries() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    engine
        .create_entry(root, new_entry("e1", vec!["alpha".into(), "shared".into()]))
        .expect("e1");
    engine
        .create_entry(root, new_entry("e2", vec!["bravo".into(), "shared".into()]))
        .expect("e2");
    engine
        .create_entry(root, new_entry("e3", vec!["charlie".into()]))
        .expect("e3");

    let tags = engine.list_tags().expect("list_tags");
    assert_eq!(
        tags,
        vec![
            "alpha".to_owned(),
            "bravo".to_owned(),
            "charlie".to_owned(),
            "shared".to_owned(),
        ]
    );
}

/// Documents the current `set_tags` cleanup behaviour: it deletes
/// rows from `entry_tag` but does **not** garbage-collect orphaned
/// `tag` rows. `list_tags` joins against `entry_tag` precisely so
/// that those orphans don't leak into the result.
///
/// If `set_tags` ever starts cleaning up `tag` rows, this test still
/// passes — it asserts the user-visible contract, not the underlying
/// mechanism.
#[test]
fn list_tags_excludes_tags_with_zero_entries_after_set_tags() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("e1", vec!["doomed".into(), "kept".into()]))
        .expect("create");

    // Confirm baseline: both tags surface.
    let before = engine.list_tags().expect("list_tags before");
    assert_eq!(before, vec!["doomed".to_owned(), "kept".to_owned()]);

    // Remove "doomed" — no other entry references it, so it should
    // disappear from the vault-wide list.
    engine
        .set_tags(uuid, vec!["kept".into()])
        .expect("set_tags");

    let after = engine.list_tags().expect("list_tags after");
    assert_eq!(after, vec!["kept".to_owned()]);
}

#[test]
fn set_tags_removes_orphan_tags() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    let db_path = dir.path().join("keys.db");
    let uuid = engine
        .create_entry(root, new_entry("e1", vec!["x".into()]))
        .expect("create");
    assert_eq!(raw_tag_names(&db_path), vec!["x".to_owned()]);

    engine.set_tags(uuid, Vec::new()).expect("set_tags");

    // The tag table itself must be empty, not just the JOIN view.
    assert!(
        raw_tag_names(&db_path).is_empty(),
        "expected tag table to be GC'd"
    );
    assert!(engine.list_tags().expect("list_tags").is_empty());
}

#[test]
fn set_tags_keeps_shared_tags() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    let db_path = dir.path().join("keys.db");
    let e1 = engine
        .create_entry(root, new_entry("e1", vec!["x".into()]))
        .expect("e1");
    let _e2 = engine
        .create_entry(root, new_entry("e2", vec!["x".into()]))
        .expect("e2");

    // Drop "x" from e1 only — e2 still references it, so the tag row
    // must stay.
    engine.set_tags(e1, Vec::new()).expect("set_tags");

    assert_eq!(raw_tag_names(&db_path), vec!["x".to_owned()]);
    assert_eq!(engine.list_tags().expect("list_tags"), vec!["x".to_owned()]);
}

#[test]
fn delete_entry_removes_orphan_tags() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    let db_path = dir.path().join("keys.db");
    let e1 = engine
        .create_entry(root, new_entry("e1", vec!["solo".into(), "shared".into()]))
        .expect("e1");
    let _e2 = engine
        .create_entry(root, new_entry("e2", vec!["shared".into()]))
        .expect("e2");
    assert_eq!(
        raw_tag_names(&db_path),
        vec!["shared".to_owned(), "solo".to_owned()]
    );

    engine.delete_entry(e1).expect("delete_entry");

    // "solo" had only e1 referencing it; "shared" still has e2.
    assert_eq!(raw_tag_names(&db_path), vec!["shared".to_owned()]);
    assert_eq!(
        engine.list_tags().expect("list_tags"),
        vec!["shared".to_owned()]
    );
}

#[test]
fn delete_group_cascade_removes_orphan_tags() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    let db_path = dir.path().join("keys.db");
    let doomed_group = engine
        .create_group(root, new_group("doomed"))
        .expect("create_group");
    let _e1 = engine
        .create_entry(
            doomed_group,
            new_entry("e1", vec!["solo".into(), "shared".into()]),
        )
        .expect("e1");
    let _e2 = engine
        .create_entry(root, new_entry("e2", vec!["shared".into()]))
        .expect("e2");
    assert_eq!(
        raw_tag_names(&db_path),
        vec!["shared".to_owned(), "solo".to_owned()]
    );

    // Cascade delete must drop "solo" (only e1 used it) but keep
    // "shared" (e2 outside the cascade still uses it).
    engine.delete_group(doomed_group).expect("delete_group");

    assert_eq!(raw_tag_names(&db_path), vec!["shared".to_owned()]);
    assert_eq!(
        engine.list_tags().expect("list_tags"),
        vec!["shared".to_owned()]
    );
}

/// Sanity check that the simplified `SELECT FROM tag` matches what the
/// old `SELECT DISTINCT JOIN` query would have returned, across a mix
/// of mutations that exercise the GC paths.
#[test]
fn list_tags_returns_same_after_gc() {
    let (mut engine, root, dir) = engine_with_empty_vault();
    let db_path = dir.path().join("keys.db");

    let e1 = engine
        .create_entry(root, new_entry("e1", vec!["a".into(), "b".into()]))
        .expect("e1");
    let e2 = engine
        .create_entry(root, new_entry("e2", vec!["b".into(), "c".into()]))
        .expect("e2");
    let _e3 = engine
        .create_entry(root, new_entry("e3", vec!["c".into(), "d".into()]))
        .expect("e3");

    // Cycle through mutations that exercise every GC entry point.
    engine.set_tags(e1, vec!["b".into()]).expect("set_tags"); // "a" orphan
    engine.delete_entry(e2).expect("delete_entry"); // no new orphans (b/c still used)

    // Compare the simplified list_tags against the explicit DISTINCT
    // JOIN query — they must agree if the GC is correct.
    let via_api = engine.list_tags().expect("list_tags");
    let via_join: Vec<String> = {
        let conn = raw_open(&db_path);
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT t.name FROM tag t \
                 JOIN entry_tag et ON et.tag_id = t.id \
                 ORDER BY t.name ASC",
            )
            .expect("prepare");
        stmt.query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect")
    };
    assert_eq!(via_api, via_join);
    // And the raw table should match too — proof the GC really cleaned.
    assert_eq!(raw_tag_names(&db_path), via_api);
}
