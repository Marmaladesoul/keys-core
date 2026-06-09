//! Integration tests for `Engine::tag_usage_counts` — the single
//! `GROUP BY` query that backs the Settings → Tags usage column.
//!
//! Covers: empty vault, single-entry multi-tag, shared-vs-unique tag
//! counts, recycle-bin inclusion (preserves legacy
//! `TagListStore::usageCount` behaviour fed `allEntriesIncludingRecycleBin`),
//! zero-entry tags absent, and case-insensitive name ordering.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, Engine, IconRef, KeyProvider, KeyProviderError, NewEntryFields, NewGroupFields,
};
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
fn empty_vault_returns_empty_vec() {
    let (engine, _root, _dir) = engine_with_empty_vault();
    let counts = engine.tag_usage_counts().expect("tag_usage_counts");
    assert!(counts.is_empty(), "expected no counts, got {counts:?}");
}

#[test]
fn untagged_entries_yield_no_counts() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    engine
        .create_entry(root, new_entry("u1", Vec::new()))
        .expect("create");
    engine
        .create_entry(root, new_entry("u2", Vec::new()))
        .expect("create");
    let counts = engine.tag_usage_counts().expect("tag_usage_counts");
    assert!(counts.is_empty(), "expected no counts, got {counts:?}");
}

#[test]
fn single_entry_with_two_tags_each_count_is_one() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    engine
        .create_entry(root, new_entry("e1", vec!["alpha".into(), "beta".into()]))
        .expect("create");
    let counts = engine.tag_usage_counts().expect("tag_usage_counts");
    assert_eq!(
        counts,
        vec![("alpha".to_owned(), 1), ("beta".to_owned(), 1)]
    );
}

#[test]
fn shared_and_unique_tags_distinct_counts() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    engine
        .create_entry(root, new_entry("e1", vec!["shared".into(), "solo".into()]))
        .expect("e1");
    engine
        .create_entry(root, new_entry("e2", vec!["shared".into()]))
        .expect("e2");
    let counts = engine.tag_usage_counts().expect("tag_usage_counts");
    assert_eq!(
        counts,
        vec![("shared".to_owned(), 2), ("solo".to_owned(), 1)]
    );
}

#[test]
fn recycled_entries_count_toward_totals() {
    // The Swift `TagListStore::usageCount` was fed
    // `allEntriesIncludingRecycleBin` — preserve that behaviour. A tag
    // referenced only by a recycled entry should still surface with
    // count 1.
    let (mut engine, root, _dir) = engine_with_empty_vault();
    // Designate a real bin group so `recycle_entry` soft-deletes (moves into
    // the bin) rather than permanently deleting. Enabling without a bin group
    // (`set_recycle_bin(true, None)`) leaves no bin to move into, so a recycle
    // would hard-delete + tombstone (KeePass "no bin = permanent delete").
    let bin = engine
        .create_group(
            root,
            NewGroupFields {
                name: "Recycle Bin".into(),
                notes: String::new(),
                icon: IconRef::Builtin(43),
            },
        )
        .expect("create bin");
    engine
        .set_recycle_bin(true, Some(bin))
        .expect("set_recycle_bin");

    let live = engine
        .create_entry(root, new_entry("live", vec!["shared".into()]))
        .expect("live");
    let _ = live;
    let doomed = engine
        .create_entry(
            root,
            new_entry("doomed", vec!["shared".into(), "only-recycled".into()]),
        )
        .expect("doomed");

    engine.recycle_entry(doomed).expect("recycle_entry");

    let counts = engine.tag_usage_counts().expect("tag_usage_counts");
    assert_eq!(
        counts,
        vec![("only-recycled".to_owned(), 1), ("shared".to_owned(), 2)],
        "recycled entries must contribute to counts"
    );
}

#[test]
fn zero_entry_tags_absent_after_set_tags_clears_last_reference() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    let uuid = engine
        .create_entry(root, new_entry("e1", vec!["doomed".into(), "kept".into()]))
        .expect("create");

    // Baseline: both tags present.
    let before = engine.tag_usage_counts().expect("before");
    assert_eq!(
        before,
        vec![("doomed".to_owned(), 1), ("kept".to_owned(), 1)]
    );

    engine
        .set_tags(uuid, vec!["kept".into()])
        .expect("set_tags");

    let after = engine.tag_usage_counts().expect("after");
    assert_eq!(after, vec![("kept".to_owned(), 1)]);
}

#[test]
fn results_sorted_by_name_case_insensitive() {
    let (mut engine, root, _dir) = engine_with_empty_vault();
    engine
        .create_entry(
            root,
            new_entry(
                "e1",
                vec![
                    "Charlie".into(),
                    "alpha".into(),
                    "BRAVO".into(),
                    "delta".into(),
                ],
            ),
        )
        .expect("create");
    let counts = engine.tag_usage_counts().expect("tag_usage_counts");
    let names: Vec<&str> = counts.iter().map(|(n, _)| n.as_str()).collect();
    // COLLATE NOCASE: alpha < BRAVO < Charlie < delta regardless of case.
    assert_eq!(names, vec!["alpha", "BRAVO", "Charlie", "delta"]);
}
