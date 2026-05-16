//! Integration tests for [`Engine::group_tree`] (task 3.2).
//!
//! Same wiring as `entry_reads.rs` — build a KDBX with the editor API,
//! ingest into a fresh engine, assert on the returned flat group list.
//!
//! Recycle-bin counting note: regular groups exclude `is_recycled = 1`
//! entries from `entry_count_direct`; the recycle bin group itself
//! includes its contents (otherwise the bin would always read 0 and
//! the UI couldn't surface "you have N items to empty").

use std::sync::Arc;
use std::time::Instant;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{NewEntry, NewGroup};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};

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

// ── tests ───────────────────────────────────────────────────────────────

#[test]
fn group_tree_returns_root_for_empty_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let tree = engine.group_tree().expect("group_tree");
    assert_eq!(tree.len(), 1, "empty vault has just the root group");
    assert_eq!(tree[0].uuid, root.0);
    assert_eq!(tree[0].parent_uuid, None);
    assert_eq!(tree[0].entry_count_direct, 0);
    assert!(!tree[0].is_recycle_bin);
}

#[test]
fn group_tree_returns_nested_hierarchy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let a = kdbx.add_group(root, NewGroup::new("A")).expect("add A");
    let b = kdbx.add_group(root, NewGroup::new("B")).expect("add B");
    let a1 = kdbx.add_group(a, NewGroup::new("A1")).expect("add A1");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let tree = engine.group_tree().expect("group_tree");
    assert_eq!(tree.len(), 4);

    // Root comes first (only one with parent_uuid = None).
    assert_eq!(tree[0].uuid, root.0);
    assert_eq!(tree[0].parent_uuid, None);

    // Remaining ordered alphabetically by name.
    let by_uuid = |u: uuid::Uuid| tree.iter().find(|n| n.uuid == u).expect("present");
    assert_eq!(by_uuid(a.0).parent_uuid, Some(root.0));
    assert_eq!(by_uuid(b.0).parent_uuid, Some(root.0));
    assert_eq!(by_uuid(a1.0).parent_uuid, Some(a.0));

    let non_root_names: Vec<&str> = tree.iter().skip(1).map(|n| n.name.as_str()).collect();
    let mut sorted = non_root_names.clone();
    sorted.sort_unstable();
    assert_eq!(non_root_names, sorted, "siblings sorted alphabetically");
}

#[test]
fn group_tree_marks_recycle_bin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let bin = kdbx
        .add_group(root, NewGroup::new("Recycle Bin"))
        .expect("add bin");
    kdbx.set_recycle_bin(true, Some(bin));

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let tree = engine.group_tree().expect("group_tree");
    let bins: Vec<_> = tree.iter().filter(|n| n.is_recycle_bin).collect();
    assert_eq!(bins.len(), 1, "exactly one recycle-bin group");
    assert_eq!(bins[0].uuid, bin.0);
}

#[test]
fn group_tree_counts_direct_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let sub = kdbx.add_group(root, NewGroup::new("Sub")).expect("add sub");

    for i in 0..2 {
        kdbx.add_entry(root, NewEntry::new(format!("r{i}")))
            .expect("add root entry");
    }
    for i in 0..3 {
        kdbx.add_entry(sub, NewEntry::new(format!("s{i}")))
            .expect("add sub entry");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let tree = engine.group_tree().expect("group_tree");
    let by_uuid = |u: uuid::Uuid| tree.iter().find(|n| n.uuid == u).expect("present");
    assert_eq!(by_uuid(root.0).entry_count_direct, 2);
    assert_eq!(by_uuid(sub.0).entry_count_direct, 3);
}

#[test]
fn group_tree_skips_recycled_entries_in_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let normal = kdbx
        .add_group(root, NewGroup::new("Normal"))
        .expect("add normal");
    let bin = kdbx
        .add_group(root, NewGroup::new("Recycle Bin"))
        .expect("add bin");
    kdbx.set_recycle_bin(true, Some(bin));

    // Normal group: 1 live entry.
    kdbx.add_entry(normal, NewEntry::new("live"))
        .expect("add live");
    // Recycle bin: 2 recycled entries (entries inside the bin are
    // flagged is_recycled by ingest).
    for i in 0..2 {
        kdbx.add_entry(bin, NewEntry::new(format!("trash{i}")))
            .expect("add trash");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let tree = engine.group_tree().expect("group_tree");
    let by_uuid = |u: uuid::Uuid| tree.iter().find(|n| n.uuid == u).expect("present");

    // Regular group counts only non-recycled entries.
    assert_eq!(by_uuid(normal.0).entry_count_direct, 1);
    // Root has no direct entries.
    assert_eq!(by_uuid(root.0).entry_count_direct, 0);
    // Recycle bin counts its own contents — that's the interesting
    // number for the UI.
    assert_eq!(by_uuid(bin.0).entry_count_direct, 2);
}

#[test]
fn group_tree_returns_stable_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    for name in ["Charlie", "Alpha", "Bravo"] {
        kdbx.add_group(root, NewGroup::new(name)).expect("add");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let first = engine.group_tree().expect("first");
    let second = engine.group_tree().expect("second");
    assert_eq!(first, second, "two calls return identical ordering");

    let names: Vec<&str> = first.iter().skip(1).map(|n| n.name.as_str()).collect();
    assert_eq!(names, ["Alpha", "Bravo", "Charlie"]);
}

#[test]
#[ignore = "perf — run with --ignored"]
fn group_tree_perf_large() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    for i in 0..100 {
        kdbx.add_group(root, NewGroup::new(format!("g{i:03}")))
            .expect("add");
    }

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let start = Instant::now();
    let tree = engine.group_tree().expect("group_tree");
    let elapsed = start.elapsed();
    assert_eq!(tree.len(), 101);
    assert!(
        elapsed.as_millis() < 50,
        "group_tree on 100-group vault took {elapsed:?}, expected < 50ms"
    );
}
