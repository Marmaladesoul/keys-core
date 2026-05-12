//! Integration tests for slice 8I-D — Vault accessors that re-export
//! keepass-core's `Vault::custom_icon`, `Vault::group_parent`, and
//! `Group::all_subgroups` across the FFI boundary.

use std::path::PathBuf;

use keys_ffi::{Vault, VaultError};

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
        "test-icons-109".to_owned(),
        None,
    )
    .expect("custom-icons fixture should open")
}

fn open_deep_groups() -> std::sync::Arc<Vault> {
    Vault::new(
        fixture("keepassxc/kdbx3-deep-groups.kdbx"),
        "test-deep-006".to_owned(),
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
