//! Integration tests for the entry-listing query surface (task 3.1):
//! [`Engine::list_entries`], [`Engine::entry`], [`Engine::entry_count`].
//!
//! Each test builds an in-memory KDBX via
//! `keepass_core::Kdbx::create_empty_v4_with_protector` + the editor
//! methods, ingests it into a fresh engine, then asserts on the
//! response of the query method under test. Same shape as the
//! `ingest.rs` integration tests.

use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{CustomFieldValue, HistoryPolicy, NewEntry, NewGroup};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    DbKey, Engine, IconRef, KeyProvider, KeyProviderError, Pagination, StrengthBucket,
};
use secrecy::SecretString;
use uuid::Uuid;

// ── test wiring ────────────────────────────────────────────────────────

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

fn fresh_kdbx() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(protector())).expect("create")
}

fn open_engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open engine")
}

/// Force `modified_at` on an entry to a deterministic timestamp so
/// list ordering is testable. The KDBX editor stamps `now()` on every
/// edit, which produces ties in tight test loops.
fn set_modified_at(kdbx: &mut Kdbx<Unlocked>, entry_uuid: keepass_core::model::EntryId, ms: i64) {
    let mut vault = kdbx.vault().clone();
    for entry in walk_entries_mut(&mut vault.root) {
        if entry.id == entry_uuid {
            entry.times.last_modification_time = Utc.timestamp_millis_opt(ms).single();
        }
    }
    kdbx.replace_vault(vault);
}

fn walk_entries_mut(
    group: &mut keepass_core::model::Group,
) -> Vec<&mut keepass_core::model::Entry> {
    let mut out: Vec<&mut keepass_core::model::Entry> = Vec::new();
    out.extend(group.entries.iter_mut());
    for child in &mut group.groups {
        out.extend(walk_entries_mut(child));
    }
    out
}

// ── list_entries ───────────────────────────────────────────────────────

#[test]
fn list_entries_returns_all_when_group_none_and_page_all() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    for i in 0..5 {
        kdbx.add_entry(root, NewEntry::new(format!("e{i}")))
            .expect("add");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let rows = engine.list_entries(None, Pagination::all()).expect("list");
    assert_eq!(rows.len(), 5);
}

#[test]
fn list_entries_filters_by_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let group_a = kdbx
        .add_group(root, NewGroup::new("A"))
        .expect("add group A");
    let group_b = kdbx
        .add_group(root, NewGroup::new("B"))
        .expect("add group B");

    for i in 0..3 {
        kdbx.add_entry(group_a, NewEntry::new(format!("a{i}")))
            .expect("add a");
    }
    for i in 0..2 {
        kdbx.add_entry(group_b, NewEntry::new(format!("b{i}")))
            .expect("add b");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let in_a = engine
        .list_entries(Some(group_a.0), Pagination::all())
        .expect("list a");
    assert_eq!(in_a.len(), 3);
    assert!(in_a.iter().all(|e| e.group_uuid == group_a.0));

    let in_b = engine
        .list_entries(Some(group_b.0), Pagination::all())
        .expect("list b");
    assert_eq!(in_b.len(), 2);
    assert!(in_b.iter().all(|e| e.group_uuid == group_b.0));
}

#[test]
fn list_entries_paginates_with_stable_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    // 10 entries with strictly decreasing modified_at, so order is
    // deterministic: entry 9 (newest) → entry 0 (oldest).
    let mut ids = Vec::new();
    for i in 0..10 {
        let id = kdbx
            .add_entry(root, NewEntry::new(format!("e{i}")))
            .expect("add");
        ids.push((i, id));
    }
    for (i, id) in &ids {
        // Index 9 → ms 10_000, index 0 → ms 1_000.
        set_modified_at(&mut kdbx, *id, 1_000 + i64::from(*i) * 1_000);
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let page1 = engine
        .list_entries(
            None,
            Pagination {
                offset: 0,
                limit: 3,
            },
        )
        .expect("p1");
    let page2 = engine
        .list_entries(
            None,
            Pagination {
                offset: 3,
                limit: 3,
            },
        )
        .expect("p2");

    assert_eq!(page1.len(), 3);
    assert_eq!(page2.len(), 3);

    // Most-recently-modified first: indices 9, 8, 7 in page 1.
    assert_eq!(page1[0].title, "e9");
    assert_eq!(page1[1].title, "e8");
    assert_eq!(page1[2].title, "e7");
    assert_eq!(page2[0].title, "e6");
    assert_eq!(page2[1].title, "e5");
    assert_eq!(page2[2].title, "e4");

    // No overlap.
    let p1_uuids: Vec<Uuid> = page1.iter().map(|e| e.uuid).collect();
    let p2_uuids: Vec<Uuid> = page2.iter().map(|e| e.uuid).collect();
    assert!(p1_uuids.iter().all(|u| !p2_uuids.contains(u)));
}

#[test]
fn list_entries_attachment_count_is_correct() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();

    let root = kdbx.vault().root.id;
    let with_two = kdbx.add_entry(root, NewEntry::new("two")).expect("add");
    let no_atts = kdbx.add_entry(root, NewEntry::new("none")).expect("add");

    kdbx.edit_entry(with_two, HistoryPolicy::NoSnapshot, |e| {
        e.attach("one.txt", b"a-bytes".to_vec(), false);
        e.attach("two.txt", b"b-bytes".to_vec(), false);
    })
    .expect("attach two");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let rows = engine.list_entries(None, Pagination::all()).expect("list");
    let with_two_row = rows.iter().find(|e| e.uuid == with_two.0).expect("found");
    let no_atts_row = rows.iter().find(|e| e.uuid == no_atts.0).expect("found");
    assert_eq!(with_two_row.attachment_count, 2);
    assert_eq!(no_atts_row.attachment_count, 0);
}

#[test]
fn list_entries_handles_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let rows = engine.list_entries(None, Pagination::all()).expect("list");
    assert!(rows.is_empty());
}

#[test]
fn list_entries_summary_strength_bucket_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    let plaintext = "Tr0ub4dor&3";
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("acme").password(SecretString::from(plaintext)),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    let expected_bucket = engine.strength(plaintext).bucket;
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let rows = engine.list_entries(None, Pagination::all()).expect("list");
    let row = rows.iter().find(|e| e.uuid == id.0).expect("found");
    let bucket = row.password_strength_bucket.expect("bucket present");
    // `expected_bucket` is `crate::strength::StrengthBucket`; both
    // enums share the `repr(u8)` discriminant. Compare via discriminant
    // to avoid pulling a cross-crate conversion into the test.
    assert_eq!(bucket as u8, expected_bucket as u8);
    // Make sure the typed enum decode path picks something other than
    // VeryWeak for this known-mid-strength password.
    assert!(matches!(
        bucket,
        StrengthBucket::Weak
            | StrengthBucket::Reasonable
            | StrengthBucket::Strong
            | StrengthBucket::VeryStrong
    ));
}

#[test]
fn list_entries_summary_url_host_extracted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("with url").url("https://login.example.com/path"),
        )
        .expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let rows = engine.list_entries(None, Pagination::all()).expect("list");
    let row = rows.iter().find(|e| e.uuid == id.0).expect("found");
    assert_eq!(row.url_host, "login.example.com");
    assert_eq!(row.url, "https://login.example.com/path");
}

// ── entry ──────────────────────────────────────────────────────────────

#[test]
fn entry_returns_none_for_missing_uuid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx();

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let res = engine.entry(Uuid::new_v4()).expect("entry");
    assert!(res.is_none());
}

#[test]
fn entry_returns_full_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();

    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("rich")
                .username("u")
                .url("https://example.com")
                .notes("notes!")
                .password(SecretString::from("pw"))
                .tags(vec!["alpha".into(), "beta".into()]),
        )
        .expect("add");
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_field(
            "Token",
            CustomFieldValue::Protected(SecretString::from("secret")),
        );
    })
    .expect("edit cf");

    // Attach a binary via the editor API.
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("file.bin", b"attachment".to_vec(), false);
    })
    .expect("attach");

    // Two history snapshots via two snapshotting edits.
    for new_title in ["rich-v1", "rich-v2"] {
        kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
            e.set_title(new_title);
        })
        .expect("edit");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let full = engine.entry(id.0).expect("entry").expect("some");
    assert_eq!(full.uuid, id.0);
    assert_eq!(full.title, "rich-v2");
    assert_eq!(full.username, "u");
    assert_eq!(full.url, "https://example.com");
    assert_eq!(full.url_host, "example.com");
    assert_eq!(full.notes, "notes!");
    assert!(!full.is_recycled);
    assert_eq!(full.tags, vec!["alpha".to_string(), "beta".to_string()]);
    assert_eq!(full.attachments.len(), 1);
    assert_eq!(full.attachments[0].name, "file.bin");
    assert_eq!(full.attachments[0].size, b"attachment".len() as u64);

    // Protected custom field surfaces; the canonical Password slot is
    // filtered out (callers fetch via reveal_password).
    assert_eq!(full.custom_fields.len(), 1);
    assert_eq!(full.custom_fields[0].name, "Token");
    assert!(full.custom_fields[0].is_protected);

    assert_eq!(full.history_count, 2);
}

// ── entry_count ────────────────────────────────────────────────────────

#[test]
fn entry_count_total() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    for i in 0..10 {
        kdbx.add_entry(root, NewEntry::new(format!("e{i}")))
            .expect("add");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    assert_eq!(engine.entry_count(None).expect("count"), 10);
}

#[test]
fn entry_count_per_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let group_a = kdbx.add_group(root, NewGroup::new("A")).expect("add");
    let group_b = kdbx.add_group(root, NewGroup::new("B")).expect("add");
    for i in 0..3 {
        kdbx.add_entry(group_a, NewEntry::new(format!("a{i}")))
            .expect("add");
    }
    for i in 0..5 {
        kdbx.add_entry(group_b, NewEntry::new(format!("b{i}")))
            .expect("add");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    assert_eq!(engine.entry_count(Some(group_a.0)).expect("a"), 3);
    assert_eq!(engine.entry_count(Some(group_b.0)).expect("b"), 5);
    assert_eq!(engine.entry_count(None).expect("all"), 8);
}

// ── icon round-trip (spot check) ───────────────────────────────────────

#[test]
fn list_entries_icon_defaults_to_builtin_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("plain")).expect("add");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let rows = engine.list_entries(None, Pagination::all()).expect("list");
    let row = rows.iter().find(|e| e.uuid == id.0).expect("found");
    assert_eq!(row.icon, IconRef::Builtin(0));
}

// ── perf ───────────────────────────────────────────────────────────────

#[test]
#[ignore = "perf benchmark — run with --ignored to confirm <50ms list of 877 entries"]
fn list_entries_perf_877() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    for i in 0..877 {
        kdbx.add_entry(
            root,
            NewEntry::new(format!("entry {i}"))
                .username(format!("user{i}"))
                .url(format!("https://host{i}.example.com"))
                .password(SecretString::from(format!("pw-{i}-{}", "x".repeat(16)))),
        )
        .expect("add");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let start = std::time::Instant::now();
    let rows = engine.list_entries(None, Pagination::all()).expect("list");
    let elapsed = start.elapsed();
    eprintln!("877-entry list took {elapsed:?}");
    assert_eq!(rows.len(), 877);
    assert!(
        elapsed < Duration::from_millis(50),
        "877-entry list must complete in <50ms, took {elapsed:?}",
    );
}
