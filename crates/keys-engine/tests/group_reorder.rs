//! Integration tests for [`Engine::reorder_group`] and the
//! `GroupsReordered` change event (migration 0004).
//!
//! Covers ingest preserving KDBX positional order, the engine's
//! reorder mutation rewriting `sort_order` for every affected sibling,
//! the event fires, error paths, and a full save → re-ingest round
//! trip so the persisted ordering survives a KDBX serialise.

use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewGroup;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{
    ChangeEvent, DataChangeObserver, DbKey, Engine, EngineError, IconRef, KeyProvider,
    KeyProviderError, NewGroupFields,
};
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

fn fresh_kdbx(p: Arc<dyn FieldProtector>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(b"pw");
    Kdbx::create_empty_v4_with_protector(&composite, "test", Some(p)).expect("create")
}

fn engine_with_three_siblings() -> (Engine, Uuid, [Uuid; 3], tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id.0;
    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    let a = engine
        .create_group(root, new_group_fields("A"))
        .expect("create A");
    let b = engine
        .create_group(root, new_group_fields("B"))
        .expect("create B");
    let c = engine
        .create_group(root, new_group_fields("C"))
        .expect("create C");
    (engine, root, [a, b, c], dir)
}

fn new_group_fields(name: &str) -> NewGroupFields {
    NewGroupFields {
        name: name.into(),
        notes: String::new(),
        icon: IconRef::Builtin(0),
    }
}

#[derive(Default, Debug)]
struct CaptureObserver {
    events: Mutex<Vec<ChangeEvent>>,
}

impl CaptureObserver {
    fn snapshot(&self) -> Vec<ChangeEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl DataChangeObserver for CaptureObserver {
    fn on_event(&self, event: ChangeEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn siblings_under(engine: &Engine, parent: Uuid) -> Vec<Uuid> {
    let tree = engine.group_tree().expect("group_tree");
    let mut kids: Vec<&keys_engine::GroupNode> = tree
        .iter()
        .filter(|n| n.parent_uuid == Some(parent))
        .collect();
    kids.sort_by_key(|n| n.sort_order);
    kids.into_iter().map(|n| n.uuid).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn create_group_appends_sort_order_after_existing_siblings() {
    let (engine, root, [a, b, c], _dir) = engine_with_three_siblings();
    let tree = engine.group_tree().expect("tree");
    let by_uuid = |u: Uuid| tree.iter().find(|n| n.uuid == u).expect("present");
    assert_eq!(by_uuid(a).sort_order, 0);
    assert_eq!(by_uuid(b).sort_order, 1);
    assert_eq!(by_uuid(c).sort_order, 2);
    assert_eq!(siblings_under(&engine, root), vec![a, b, c]);
}

#[test]
fn reorder_group_within_parent_reorders_siblings() {
    let (mut engine, root, [a, b, c], _dir) = engine_with_three_siblings();
    // Move B to the last slot: expected [A, C, B].
    engine.reorder_group(b, 2).expect("reorder");
    assert_eq!(siblings_under(&engine, root), vec![a, c, b]);
    let tree = engine.group_tree().expect("tree");
    let by_uuid = |u: Uuid| tree.iter().find(|n| n.uuid == u).expect("present");
    assert_eq!(by_uuid(a).sort_order, 0);
    assert_eq!(by_uuid(c).sort_order, 1);
    assert_eq!(by_uuid(b).sort_order, 2);
}

#[test]
fn reorder_group_clamps_position_past_end() {
    let (mut engine, root, [a, b, c], _dir) = engine_with_three_siblings();
    // Caller passed a wildly out-of-range position; should land last.
    engine.reorder_group(a, 99).expect("reorder");
    assert_eq!(siblings_under(&engine, root), vec![b, c, a]);
}

#[test]
fn reorder_group_to_front_works() {
    let (mut engine, root, [a, b, c], _dir) = engine_with_three_siblings();
    engine.reorder_group(c, 0).expect("reorder");
    assert_eq!(siblings_under(&engine, root), vec![c, a, b]);
}

#[test]
fn reorder_group_emits_event() {
    let (mut engine, _root, [a, b, c], _dir) = engine_with_three_siblings();
    let observer = Arc::new(CaptureObserver::default());
    engine.set_observer(observer.clone());
    engine.reorder_group(b, 2).expect("reorder");
    let events = observer.snapshot();
    assert_eq!(events.len(), 1, "exactly one event for a reorder");
    match &events[0] {
        ChangeEvent::GroupsReordered(v) => {
            // Carries the full new sibling order.
            assert_eq!(v, &vec![a, c, b]);
        }
        other => panic!("expected GroupsReordered, got {other:?}"),
    }
}

#[test]
fn reorder_returns_not_found_for_missing_uuid() {
    let (mut engine, _root, _siblings, _dir) = engine_with_three_siblings();
    let err = engine.reorder_group(Uuid::new_v4(), 0).unwrap_err();
    assert!(
        matches!(err, EngineError::NotFound { entity: "group" }),
        "expected NotFound, got {err:?}",
    );
}

#[test]
fn reorder_returns_not_found_for_root() {
    // The root group has no siblings; we report it as not-found rather
    // than silently no-op'ing.
    let (mut engine, root, _siblings, _dir) = engine_with_three_siblings();
    let err = engine.reorder_group(root, 0).unwrap_err();
    assert!(
        matches!(err, EngineError::NotFound { entity: "group" }),
        "expected NotFound, got {err:?}",
    );
}

#[test]
fn group_tree_returns_groups_in_sort_order() {
    let (mut engine, root, [a, b, c], _dir) = engine_with_three_siblings();
    // Reorder twice so the tree definitely isn't returning insertion order
    // by accident.
    engine.reorder_group(c, 0).expect("c -> 0"); // [C, A, B]
    engine.reorder_group(a, 2).expect("a -> 2"); // [C, B, A]
    let tree = engine.group_tree().expect("tree");
    // Drop the root for this assertion.
    let order: Vec<Uuid> = tree
        .iter()
        .filter(|n| n.parent_uuid == Some(root))
        .map(|n| n.uuid)
        .collect();
    assert_eq!(order, vec![c, b, a]);
}

#[test]
fn ingest_preserves_kdbx_positional_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    // Add in a deliberately non-alphabetical order.
    let charlie = kdbx
        .add_group(root, NewGroup::new("Charlie"))
        .expect("add Charlie");
    let alpha = kdbx
        .add_group(root, NewGroup::new("Alpha"))
        .expect("add Alpha");
    let bravo = kdbx
        .add_group(root, NewGroup::new("Bravo"))
        .expect("add Bravo");

    let mut engine = Engine::open(&path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let tree = engine.group_tree().expect("tree");
    let by_uuid = |u: Uuid| tree.iter().find(|n| n.uuid == u).expect("present");
    assert_eq!(by_uuid(charlie.0).sort_order, 0);
    assert_eq!(by_uuid(alpha.0).sort_order, 1);
    assert_eq!(by_uuid(bravo.0).sort_order, 2);
}

#[test]
fn save_writes_groups_in_sort_order() {
    // Build a vault with three siblings, reorder them, save back to a
    // KDBX file, re-open + re-ingest, and assert the order survived.
    let dir = tempfile::tempdir().expect("tempdir");
    let kdbx_path = dir.path().join("vault.kdbx");
    let db_path = dir.path().join("keys.db");

    let mut kdbx = fresh_kdbx(protector());
    let root = kdbx.vault().root.id;
    let _a = kdbx.add_group(root, NewGroup::new("A")).expect("add A");
    let b = kdbx.add_group(root, NewGroup::new("B")).expect("add B");
    let _c = kdbx.add_group(root, NewGroup::new("C")).expect("add C");

    let mut engine =
        Engine::open(&db_path, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    // Move B to the front: expected [B, A, C].
    engine.reorder_group(b.0, 0).expect("reorder");
    // Save back to disk.
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save_to_kdbx");
    drop(engine);
    drop(kdbx);

    // Reopen the saved KDBX from disk and re-ingest into a fresh
    // engine; the projected order should still be [B, A, C].
    let composite = CompositeKey::from_password(b"pw");
    let reopened = Kdbx::open(&kdbx_path)
        .expect("open kdbx from disk")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite, Some(protector()))
        .expect("unlock");

    let db2 = dir.path().join("keys2.db");
    let mut engine2 =
        Engine::open(&db2, &FixedKey(DB_KEY_BYTES), protector(), None).expect("open 2");
    engine2.ingest_from_kdbx(&reopened).expect("re-ingest");

    let tree = engine2.group_tree().expect("tree");
    let order: Vec<&str> = tree
        .iter()
        .filter(|n| n.parent_uuid == Some(root.0))
        .map(|n| n.name.as_str())
        .collect();
    assert_eq!(order, vec!["B", "A", "C"]);
    let positions: Vec<u32> = tree
        .iter()
        .filter(|n| n.parent_uuid == Some(root.0))
        .map(|n| n.sort_order)
        .collect();
    assert_eq!(positions, vec![0, 1, 2]);
}
