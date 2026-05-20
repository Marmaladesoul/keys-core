//! Integration tests for slice 8I-D — Vault accessors that re-export
//! keepass-core's `Vault::custom_icon`, `Vault::group_parent`, and
//! `Group::all_subgroups` across the FFI boundary.
//!
//! Slice 8I-E adds `all_entries`, `recycle_bin_enabled`, and
//! `move_group_to_position` — exercised by the additional tests below.

use std::path::PathBuf;

use keys_ffi::{Vault, VaultError};
use tempfile::TempDir;

fn fixture(rel: &str) -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../../../KeepassCore/tests/fixtures")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

fn open_custom_icons() -> std::sync::Arc<Vault> {
    Vault::new(
        fixture("pykeepass/custom-icons.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("custom-icons fixture should open")
}

fn open_basic() -> std::sync::Arc<Vault> {
    Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("basic fixture should open")
}

fn open_deep_groups() -> std::sync::Arc<Vault> {
    Vault::new(
        fixture("keepassxc/kdbx3-deep-groups.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("deep-groups fixture should open")
}

// -------------------------------------------------------------------
// custom_icon_image
// -------------------------------------------------------------------

#[test]
fn custom_icon_image_returns_bytes_for_known_uuid() {
    let vault = open_custom_icons();
    // UUID from the sidecar — pooled custom icon referenced by the
    // "With Icon" entry. The fixture source bytes are the 1x1.png.
    let bytes = vault
        .custom_icon_image("cccccccc-dddd-eeee-ffff-000000000042".to_owned())
        .expect("call succeeds")
        .expect("known icon UUID returns Some");
    assert!(!bytes.is_empty(), "icon bytes should be non-empty");
    // PNG magic header guards against accidentally returning something
    // else (e.g. an empty vec for a known icon).
    assert_eq!(&bytes[..4], b"\x89PNG", "fixture icon is a PNG");
}

#[test]
fn custom_icon_image_returns_none_for_unknown_uuid() {
    let vault = open_custom_icons();
    let out = vault
        .custom_icon_image("00000000-0000-0000-0000-000000000000".to_owned())
        .expect("unknown UUID is Ok(None), not an error");
    assert!(out.is_none());
}

#[test]
fn custom_icon_image_returns_not_found_for_invalid_uuid() {
    let vault = open_custom_icons();
    let err = vault
        .custom_icon_image("not-a-uuid".to_owned())
        .expect_err("malformed UUID surfaces as NotFound");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// -------------------------------------------------------------------
// group_parent_uuid
// -------------------------------------------------------------------

#[test]
fn group_parent_uuid_returns_parent_for_subgroup() {
    let vault = open_deep_groups();
    let groups = vault.list_groups().expect("groups");
    let level2 = groups
        .iter()
        .find(|g| g.name == "Level2")
        .expect("Level2 present");
    let level1 = groups
        .iter()
        .find(|g| g.name == "Level1")
        .expect("Level1 present");

    let parent = vault
        .group_parent_uuid(level2.uuid.clone())
        .expect("call succeeds")
        .expect("Level2 has a parent");
    assert_eq!(parent, level1.uuid);
}

#[test]
fn group_parent_uuid_returns_none_for_root() {
    let vault = open_deep_groups();
    let groups = vault.list_groups().expect("groups");
    let root = groups
        .iter()
        .find(|g| g.parent_uuid.is_none())
        .expect("root group present");

    let out = vault
        .group_parent_uuid(root.uuid.clone())
        .expect("call succeeds");
    assert!(out.is_none(), "root has no parent");
}

#[test]
fn group_parent_uuid_returns_none_for_unknown_uuid() {
    let vault = open_deep_groups();
    let out = vault
        .group_parent_uuid("00000000-0000-0000-0000-000000000000".to_owned())
        .expect("unknown UUID is Ok(None), not an error");
    assert!(out.is_none());
}

#[test]
fn group_parent_uuid_returns_not_found_for_invalid_uuid() {
    let vault = open_deep_groups();
    let err = vault
        .group_parent_uuid("not-a-uuid".to_owned())
        .expect_err("malformed UUID surfaces as NotFound");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// -------------------------------------------------------------------
// all_subgroup_uuids
// -------------------------------------------------------------------

#[test]
fn all_subgroup_uuids_walks_recursively_from_root() {
    let vault = open_deep_groups();
    let groups = vault.list_groups().expect("groups");
    let root = groups
        .iter()
        .find(|g| g.parent_uuid.is_none())
        .expect("root present");

    let subs = vault
        .all_subgroup_uuids(root.uuid.clone())
        .expect("call succeeds");
    // Sidecar declares 8 named groups under the root (Level1..Level5,
    // Parallel, ChildA, ChildB). `all_subgroups` excludes self, so
    // every non-root group should appear.
    assert_eq!(subs.len(), 8, "8 descendant groups under root");

    let by_name: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
    assert!(by_name.contains(&"Level5"));
    assert!(by_name.contains(&"ChildB"));

    // Every returned UUID must resolve to a real group in the vault.
    for uuid in &subs {
        assert!(
            groups.iter().any(|g| &g.uuid == uuid),
            "{uuid} should be a known group"
        );
        assert_ne!(uuid, &root.uuid, "self must not be included");
    }
}

#[test]
fn all_subgroup_uuids_returns_empty_for_leaf() {
    let vault = open_deep_groups();
    let groups = vault.list_groups().expect("groups");
    let level5 = groups
        .iter()
        .find(|g| g.name == "Level5")
        .expect("Level5 (leaf) present");

    let subs = vault
        .all_subgroup_uuids(level5.uuid.clone())
        .expect("call succeeds");
    assert!(subs.is_empty(), "leaf group has no subgroups");
}

#[test]
fn all_subgroup_uuids_returns_not_found_for_unknown_group() {
    let vault = open_deep_groups();
    let err = vault
        .all_subgroup_uuids("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("unknown group UUID is an error");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// -------------------------------------------------------------------
// all_entries
// -------------------------------------------------------------------

#[test]
fn all_entries_returns_every_entry() {
    // Fixture-based: walk count must match the union of
    // `list_entries(group_uuid:)` across every group surfaced by
    // `list_groups`.
    let vault = open_deep_groups();
    let groups = vault.list_groups().expect("groups");

    let mut expected_count = 0_usize;
    for g in &groups {
        let n = vault
            .list_entries(Some(g.uuid.clone()))
            .expect("per-group list")
            .len();
        expected_count += n;
    }

    let all = vault.all_entries().expect("all_entries");
    assert_eq!(
        all.len(),
        expected_count,
        "all_entries count should match the sum of per-group list_entries",
    );

    // Every returned Entry should carry a group_uuid that resolves to
    // a known group in the vault — guards against stray ID corruption
    // at the FFI boundary.
    for entry in &all {
        assert!(
            groups.iter().any(|g| g.uuid == entry.group_uuid),
            "entry {} references unknown group {}",
            entry.uuid,
            entry.group_uuid,
        );
    }
}

// -------------------------------------------------------------------
// recycle_bin_enabled
// -------------------------------------------------------------------

#[test]
fn recycle_bin_enabled_returns_meta_flag() {
    // Fresh empty vault — defaults to recycle-bin-enabled = true on
    // keepass-core's `create_empty_v4`. Toggle via `set_recycle_bin`
    // and verify both states round-trip through the FFI accessor.
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("rb.kdbx").to_string_lossy().into_owned();
    let vault =
        Vault::create_empty(path, "pw".to_owned(), "Vault".to_owned(), None).expect("create_empty");

    // Force-enable, then read.
    vault.set_recycle_bin(true, None).expect("enable");
    assert!(
        vault.recycle_bin_enabled().expect("read enabled"),
        "after set_recycle_bin(true) the flag should read back true",
    );

    // Force-disable, then read.
    vault.set_recycle_bin(false, None).expect("disable");
    assert!(
        !vault.recycle_bin_enabled().expect("read disabled"),
        "after set_recycle_bin(false) the flag should read back false",
    );
}

// -------------------------------------------------------------------
// move_group_to_position
// -------------------------------------------------------------------

fn child_uuids_in_order(vault: &Vault, parent_uuid: &str) -> Vec<String> {
    // `list_groups` is depth-first from the root, preserving sibling
    // order at each level. Filter to direct children of `parent_uuid`
    // and project to their UUIDs.
    let groups = vault.list_groups().expect("groups");
    groups
        .iter()
        .filter(|g| g.parent_uuid.as_deref() == Some(parent_uuid))
        .map(|g| g.uuid.clone())
        .collect()
}

#[test]
fn move_group_to_position_within_same_parent_reorders() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir
        .path()
        .join("reorder.kdbx")
        .to_string_lossy()
        .into_owned();
    let vault =
        Vault::create_empty(path, "pw".to_owned(), "Vault".to_owned(), None).expect("create_empty");

    let root_uuid = vault
        .list_groups()
        .expect("groups")
        .into_iter()
        .find(|g| g.parent_uuid.is_none())
        .expect("root")
        .uuid;

    // Three siblings under root, in order [a, b, c].
    let a = vault
        .create_group("a".to_owned(), Some(root_uuid.clone()))
        .expect("a");
    let b = vault
        .create_group("b".to_owned(), Some(root_uuid.clone()))
        .expect("b");
    let c = vault
        .create_group("c".to_owned(), Some(root_uuid.clone()))
        .expect("c");

    assert_eq!(
        child_uuids_in_order(&vault, &root_uuid),
        vec![a.clone(), b.clone(), c.clone()],
    );

    // Move `a` to index 2. After removal the remaining siblings are
    // [b, c]; inserting at index 2 (== len) appends → [b, c, a].
    vault
        .move_group_to_position(a.clone(), root_uuid.clone(), 2)
        .expect("reorder");
    assert_eq!(
        child_uuids_in_order(&vault, &root_uuid),
        vec![b, c, a],
        "same-parent move should act as a sibling reorder",
    );
}

#[test]
fn move_group_to_position_to_new_parent_with_index() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("move.kdbx").to_string_lossy().into_owned();
    let vault =
        Vault::create_empty(path, "pw".to_owned(), "Vault".to_owned(), None).expect("create_empty");

    let root_uuid = vault
        .list_groups()
        .expect("groups")
        .into_iter()
        .find(|g| g.parent_uuid.is_none())
        .expect("root")
        .uuid;

    // Destination parent with three existing children [c0, c1, c2].
    let parent = vault
        .create_group("Parent".to_owned(), Some(root_uuid.clone()))
        .expect("parent");
    let c0 = vault
        .create_group("c0".to_owned(), Some(parent.clone()))
        .expect("c0");
    let c1 = vault
        .create_group("c1".to_owned(), Some(parent.clone()))
        .expect("c1");
    let c2 = vault
        .create_group("c2".to_owned(), Some(parent.clone()))
        .expect("c2");

    // Group to move, currently a child of root.
    let mover = vault
        .create_group("mover".to_owned(), Some(root_uuid.clone()))
        .expect("mover");

    // Cross-parent move inserting at index 1 → [c0, mover, c1, c2].
    vault
        .move_group_to_position(mover.clone(), parent.clone(), 1)
        .expect("move with index");
    assert_eq!(
        child_uuids_in_order(&vault, &parent),
        vec![c0, mover, c1, c2],
        "cross-parent move should insert at the requested index",
    );
}

// ---------------------------------------------------------------------------
// Info-tab accessors (todo 080): generator / cipher / kdf / attachment-pool stats
// ---------------------------------------------------------------------------

#[test]
fn generator_returns_string_from_meta() {
    let vault = open_basic();
    let g = vault.generator().expect("generator");
    // KeePassXC fixtures carry "KeePassXC" as the generator string.
    assert!(
        g.contains("KeePass"),
        "generator should mention KeePass, got {g:?}"
    );
}

#[test]
fn cipher_display_recognises_aes() {
    let vault = open_basic();
    let c = vault.cipher_display().expect("cipher");
    // kdbx3-basic uses AES-256.
    assert_eq!(c, "AES-256-CBC");
}

#[test]
fn kdf_display_formats_argon2_or_aes_kdf() {
    let vault = open_basic();
    let k = vault.kdf_display().expect("kdf");
    // Either an Argon2 or AES-KDF formatted line — both contain "("
    // followed by the parameter list.
    assert!(
        k.contains("Argon2") || k.contains("AES-KDF"),
        "kdf_display should name a known KDF, got {k:?}"
    );
    assert!(
        k.contains('('),
        "should carry parenthesised params, got {k:?}"
    );
}

#[test]
fn attachment_pool_stats_counts_unique_binaries() {
    let vault = open_basic();
    let stats = vault.attachment_pool_stats().expect("stats");
    // kdbx3-basic has no attachments; smoke just confirms the call works.
    assert_eq!(
        stats.total_bytes, 0,
        "basic fixture has no attachments; total_bytes should be zero",
    );
    assert_eq!(stats.count, 0);
}

#[test]
fn accessors_return_locked_after_lock() {
    let vault = open_basic();
    vault.lock().expect("lock");
    assert!(matches!(vault.generator(), Err(VaultError::Locked)));
    assert!(matches!(vault.cipher_display(), Err(VaultError::Locked)));
    assert!(matches!(vault.kdf_display(), Err(VaultError::Locked)));
    assert!(matches!(
        vault.attachment_pool_stats(),
        Err(VaultError::Locked)
    ));
}
