//! Integration tests for [`Engine::group_tree`] (task 3.2).
//!
//! Same wiring as `entry_reads.rs` — build a KDBX with the editor API,
//! ingest into a fresh engine, assert on the returned flat group list.
//!
//! Recycle-bin counting note: `entry_count_direct` attributes every
//! entry to the group it is located in — the per-entry `is_recycled`
//! flag plays no part. The bin counts what sits directly in it, and a
//! group recycled *with* its entries keeps its own count, warm and
//! cold (the flag is warm-stale after a group recycle, so counting by
//! it made the two states disagree).

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

    let by_uuid = |u: uuid::Uuid| tree.iter().find(|n| n.uuid == u).expect("present");
    assert_eq!(by_uuid(a.0).parent_uuid, Some(root.0));
    assert_eq!(by_uuid(b.0).parent_uuid, Some(root.0));
    assert_eq!(by_uuid(a1.0).parent_uuid, Some(a.0));

    // Siblings come back in the KDBX positional order written by
    // ingest — A was added before B, so A precedes B.
    assert_eq!(by_uuid(a.0).sort_order, 0);
    assert_eq!(by_uuid(b.0).sort_order, 1);
    // A1 is the first (and only) child of A.
    assert_eq!(by_uuid(a1.0).sort_order, 0);
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
fn group_tree_counts_bin_contents_on_the_bin() {
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

    // Regular group counts its own entries.
    assert_eq!(by_uuid(normal.0).entry_count_direct, 1);
    // Root has no direct entries.
    assert_eq!(by_uuid(root.0).entry_count_direct, 0);
    // Recycle bin counts its own contents — that's the interesting
    // number for the UI.
    assert_eq!(by_uuid(bin.0).entry_count_direct, 2);
}

#[test]
fn group_tree_counts_are_by_location_not_flag_cold() {
    // The cold-mirror half of the discriminating case: a vault ingested
    // with a group already inside the bin subtree. Ingest derives
    // `is_recycled = 1` for the buried entry from ancestry, but the
    // entry is still located in its own group — the count must stay
    // attributed there. (A flag-filtered count reported this group as
    // empty while the same vault, mutated warm, reported it full.)
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let bin = kdbx
        .add_group(root, NewGroup::new("Recycle Bin"))
        .expect("add bin");
    kdbx.set_recycle_bin(true, Some(bin));
    let doomed = kdbx
        .add_group(bin, NewGroup::new("Doomed"))
        .expect("add doomed");
    kdbx.add_entry(doomed, NewEntry::new("buried"))
        .expect("add buried");
    kdbx.add_entry(bin, NewEntry::new("trashed directly"))
        .expect("add direct");

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let tree = engine.group_tree().expect("group_tree");
    let by_uuid = |u: uuid::Uuid| tree.iter().find(|n| n.uuid == u).expect("present");
    assert_eq!(
        by_uuid(doomed.0).entry_count_direct,
        1,
        "a group inside the bin keeps its own direct count"
    );
    assert_eq!(
        by_uuid(bin.0).entry_count_direct,
        1,
        "the bin counts only what sits directly in it"
    );
}

#[test]
fn group_tree_counts_are_by_location_not_flag_warm() {
    // The warm-mirror half: drive the same shape through engine
    // mutations, exercising both stale-flag directions in one live
    // mirror. After `recycle_group` the buried entry's flag is still 0
    // (a group recycle re-parents without cascading the flag); after
    // `move_entry` into the recycled group the moved entry's flag is 1.
    // Location attributes both to the group; the flag would count one
    // and drop the other.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;

    let mut engine = open_engine(&path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine.set_recycle_bin(true, None).expect("enable bin");
    engine.ensure_recycle_bin().expect("ensure bin");

    let new_entry = |title: &str| keys_engine::NewEntryFields {
        title: title.into(),
        username: String::new(),
        url: String::new(),
        notes: String::new(),
        password: secrecy::SecretString::from("pw"),
        icon: keys_engine::IconRef::Builtin(0),
        custom_fields: Vec::new(),
        tags: Vec::new(),
    };
    let doomed = engine
        .create_group(
            root.0,
            keys_engine::NewGroupFields {
                name: "Doomed".into(),
                notes: String::new(),
                icon: keys_engine::IconRef::Builtin(0),
            },
        )
        .expect("create group");
    engine
        .create_entry(doomed, new_entry("buried"))
        .expect("create buried");
    let straggler = engine
        .create_entry(root.0, new_entry("straggler"))
        .expect("create straggler");

    engine.recycle_group(doomed).expect("recycle group");
    engine
        .move_entry(straggler, doomed)
        .expect("move into recycled group");

    let tree = engine.group_tree().expect("group_tree");
    let by_uuid = |u: uuid::Uuid| tree.iter().find(|n| n.uuid == u).expect("present");
    let bin = tree
        .iter()
        .find(|n| n.is_recycle_bin)
        .expect("bin exists after ensure");
    assert_eq!(
        by_uuid(doomed).entry_count_direct,
        2,
        "flag-0 (recycled group) and flag-1 (moved-in) entries both count on their group"
    );
    assert_eq!(
        bin.entry_count_direct, 0,
        "nothing sits directly in the bin"
    );
    assert_eq!(by_uuid(root.0).entry_count_direct, 0);
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

    // KDBX positional order is what we wrote on insert; the engine
    // preserves it across migration 0004.
    let names: Vec<&str> = first.iter().skip(1).map(|n| n.name.as_str()).collect();
    assert_eq!(names, ["Charlie", "Alpha", "Bravo"]);
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
