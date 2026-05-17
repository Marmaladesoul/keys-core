//! Integration tests for `Engine::list_tags` (Phase 6.13 prep).
//!
//! Covers the vault-wide tag-list read path that replaces the Swift
//! `TagListStore`. The interesting edge case is documented in
//! `list_tags_excludes_tags_with_zero_entries_after_set_tags`: tag
//! rows linger in the `tag` table after `set_tags` removes the last
//! `entry_tag` link, and `list_tags` must filter those out.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, IconRef, KeyProvider, KeyProviderError, NewEntryFields};
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
