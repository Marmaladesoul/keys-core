//! Integration tests for [`Engine::group_parent_uuid`] and
//! [`Engine::is_descendant_of`] (task 6.17-C).
//!
//! Wiring mirrors `group_tree.rs`: build a KDBX with the editor API,
//! ingest into a fresh engine, then exercise the ancestry surface.
//!
//! Semantics under test:
//! - `group_parent_uuid` returns `Some(parent)` for non-root, `None`
//!   for the root group itself, and `NotFound` for an unknown UUID.
//! - `is_descendant_of` returns `true` for any depth of descendant,
//!   `false` for the same UUID twice (a group is not its own
//!   descendant), `false` for unrelated UUIDs, and `NotFound` if the
//!   child doesn't exist (the ancestor is not validated separately —
//!   a missing ancestor just terminates the walk at root with
//!   `false`).

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::NewGroup;
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, EngineError, KeyProvider, KeyProviderError};
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

/// Build the canonical 3-level tree used by most tests:
///
/// ```text
/// root
/// ├── a
/// │   └── a1
/// │       └── a1a
/// └── b
/// ```
struct Tree {
    root: Uuid,
    a: Uuid,
    a1: Uuid,
    a1a: Uuid,
    b: Uuid,
}

fn build_tree(path: &std::path::Path) -> (Engine, Tree) {
    let mut kdbx = fresh_kdbx();
    let root = kdbx.vault().root.id;
    let a = kdbx.add_group(root, NewGroup::new("A")).expect("add A");
    let b = kdbx.add_group(root, NewGroup::new("B")).expect("add B");
    let a1 = kdbx.add_group(a, NewGroup::new("A1")).expect("add A1");
    let a1a = kdbx.add_group(a1, NewGroup::new("A1A")).expect("add A1A");

    let mut engine = open_engine(path);
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    (
        engine,
        Tree {
            root: root.0,
            a: a.0,
            a1: a1.0,
            a1a: a1a.0,
            b: b.0,
        },
    )
}

// ── group_parent_uuid ──────────────────────────────────────────────────

#[test]
fn group_parent_uuid_non_root_returns_parent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, t) = build_tree(&path);

    assert_eq!(
        engine.group_parent_uuid(t.a).expect("parent of A"),
        Some(t.root)
    );
    assert_eq!(
        engine.group_parent_uuid(t.a1).expect("parent of A1"),
        Some(t.a)
    );
    assert_eq!(
        engine.group_parent_uuid(t.a1a).expect("parent of A1A"),
        Some(t.a1)
    );
    assert_eq!(
        engine.group_parent_uuid(t.b).expect("parent of B"),
        Some(t.root)
    );
}

#[test]
fn group_parent_uuid_root_returns_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, t) = build_tree(&path);

    assert_eq!(
        engine.group_parent_uuid(t.root).expect("parent of root"),
        None,
        "the root group has no parent"
    );
}

#[test]
fn group_parent_uuid_unknown_returns_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, _t) = build_tree(&path);

    let bogus = Uuid::new_v4();
    let err = engine
        .group_parent_uuid(bogus)
        .expect_err("unknown group → NotFound");
    assert!(
        matches!(err, EngineError::NotFound { entity: "group" }),
        "expected NotFound{{ entity: \"group\" }}, got {err:?}"
    );
}

// ── is_descendant_of ───────────────────────────────────────────────────

#[test]
fn is_descendant_of_direct_child_returns_true() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, t) = build_tree(&path);

    assert!(
        engine.is_descendant_of(t.a, t.root).expect("A under root"),
        "A is a direct child of root"
    );
    assert!(
        engine.is_descendant_of(t.a1, t.a).expect("A1 under A"),
        "A1 is a direct child of A"
    );
}

#[test]
fn is_descendant_of_grandchild_returns_true() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, t) = build_tree(&path);

    assert!(
        engine
            .is_descendant_of(t.a1, t.root)
            .expect("A1 under root"),
        "A1 is a grandchild of root"
    );
    assert!(
        engine
            .is_descendant_of(t.a1a, t.root)
            .expect("A1A under root"),
        "A1A is a great-grandchild of root"
    );
    assert!(
        engine.is_descendant_of(t.a1a, t.a).expect("A1A under A"),
        "A1A is a grandchild of A"
    );
}

#[test]
fn is_descendant_of_unrelated_returns_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, t) = build_tree(&path);

    // B and A are siblings — B is not inside A's subtree.
    assert!(
        !engine.is_descendant_of(t.b, t.a).expect("B vs A"),
        "B is a sibling of A, not a descendant"
    );
    // A1 is in A's subtree, not B's.
    assert!(
        !engine.is_descendant_of(t.a1, t.b).expect("A1 vs B"),
        "A1 is in A's subtree, not B's"
    );
    // A is not a descendant of its own child.
    assert!(
        !engine.is_descendant_of(t.a, t.a1).expect("A vs A1"),
        "ancestor walk goes up, not down"
    );
}

#[test]
fn is_descendant_of_same_uuid_returns_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, t) = build_tree(&path);

    // A group is not its own descendant (chosen non-inclusive
    // semantics — see docs on Engine::is_descendant_of).
    assert!(
        !engine.is_descendant_of(t.a, t.a).expect("A vs A"),
        "a group is not its own descendant"
    );
    assert!(
        !engine
            .is_descendant_of(t.root, t.root)
            .expect("root vs root"),
        "root is not its own descendant either"
    );
}

#[test]
fn is_descendant_of_unknown_child_returns_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, t) = build_tree(&path);

    let bogus = Uuid::new_v4();
    let err = engine
        .is_descendant_of(bogus, t.root)
        .expect_err("unknown child → NotFound");
    assert!(
        matches!(err, EngineError::NotFound { entity: "group" }),
        "expected NotFound{{ entity: \"group\" }}, got {err:?}"
    );
}

#[test]
fn is_descendant_of_unknown_ancestor_returns_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, t) = build_tree(&path);

    // A non-existent ancestor is not an error — the walk just
    // terminates at root without matching and returns false.
    let bogus = Uuid::new_v4();
    assert!(
        !engine
            .is_descendant_of(t.a1a, bogus)
            .expect("unknown ancestor → false, not error"),
        "unknown ancestor terminates walk at root with false"
    );
}

#[test]
fn is_descendant_of_root_under_anything_is_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let (engine, t) = build_tree(&path);

    // Root has no parent, so it's not a descendant of anything.
    assert!(
        !engine.is_descendant_of(t.root, t.a).expect("root vs A"),
        "root is not a descendant of any group"
    );
}
