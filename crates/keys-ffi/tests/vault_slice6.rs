//! Integration tests for slice 6 — group mutation, recycle bin,
//! meta setters, and custom icons. Combined into one file to
//! share fixtures and helpers; logically split by `mod` blocks.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use keys_ffi::{EntryCreate, GroupPatch, Vault, VaultError};
use tempfile::NamedTempFile;

fn fixture(rel: &str) -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../../../KeepassCore/tests/fixtures")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

fn open_basic() -> Arc<Vault> {
    Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "test-basic-002".to_owned(),
    )
    .expect("kdbx3-basic should open")
}

fn open_recycle() -> Arc<Vault> {
    Vault::new(
        fixture("pykeepass/recycle.kdbx"),
        "test-recycle-102".to_owned(),
    )
    .expect("recycle fixture should open")
}

fn save_and_reopen(vault: &Vault, password: &str) -> (Arc<Vault>, NamedTempFile) {
    let bytes = vault.save_to_bytes().expect("save");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    tmp.write_all(&bytes).expect("write");
    tmp.flush().expect("flush");
    let path = tmp.path().to_string_lossy().into_owned();
    let reopened = Vault::new(path, password.to_owned()).expect("reopen");
    (reopened, tmp)
}

fn root_uuid(vault: &Vault) -> String {
    vault
        .list_groups()
        .expect("groups")
        .into_iter()
        .find(|g| g.parent_uuid.is_none())
        .expect("root present")
        .uuid
}

fn group_uuid(vault: &Vault, name: &str) -> String {
    vault
        .list_groups()
        .expect("groups")
        .into_iter()
        .find(|g| g.name == name)
        .unwrap_or_else(|| panic!("group {name} present"))
        .uuid
}

const BOGUS: &str = "00000000-0000-0000-0000-000000000000";

// =======================================================================
// Group CRUD
// =======================================================================

#[test]
fn create_group_under_named_parent_appears_in_listing() {
    let vault = open_basic();
    let parent = group_uuid(&vault, "Personal");
    let new_uuid = vault
        .create_group("Subgroup".to_owned(), Some(parent.clone()))
        .expect("create");

    let groups = vault.list_groups().expect("list");
    let subgroup = groups
        .iter()
        .find(|g| g.uuid == new_uuid)
        .expect("subgroup present");
    assert_eq!(subgroup.name, "Subgroup");
    assert_eq!(subgroup.parent_uuid.as_deref(), Some(parent.as_str()));
}

#[test]
fn create_group_with_none_parent_uses_root() {
    let vault = open_basic();
    let root = root_uuid(&vault);
    let new_uuid = vault
        .create_group("TopLevel".to_owned(), None)
        .expect("create");
    let groups = vault.list_groups().expect("list");
    let g = groups.iter().find(|g| g.uuid == new_uuid).unwrap();
    assert_eq!(g.parent_uuid.as_deref(), Some(root.as_str()));
}

#[test]
fn create_group_bogus_parent_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .create_group("Doomed".to_owned(), Some(BOGUS.to_owned()))
        .expect_err("bogus parent should miss");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn update_group_sparse_patch() {
    let vault = open_basic();
    let target = group_uuid(&vault, "Personal");

    let mut patch = GroupPatch::empty();
    patch.name = Some("Personal (renamed)".to_owned());
    vault.update_group(target.clone(), patch).expect("update");

    let groups = vault.list_groups().expect("list");
    let g = groups.iter().find(|g| g.uuid == target).unwrap();
    assert_eq!(g.name, "Personal (renamed)");
}

// -----------------------------------------------------------------------
// GroupPatch icon-field surface (slice 4A PR 2)
//
// Mirrors the `EntryPatch` icon-field shape: built-in `icon_id` is set
// via the patch (single `Option<u32>`); `custom_icon_uuid` is set via
// the patch and cleared via `Vault::clear_group_custom_icon`.
// -----------------------------------------------------------------------

#[test]
fn update_group_icon_id_sets_value_and_round_trips() {
    let vault = open_basic();
    let target = group_uuid(&vault, "Personal");

    let mut patch = GroupPatch::empty();
    patch.icon_id = Some(48);
    vault.update_group(target.clone(), patch).expect("update");
    let g = vault
        .list_groups()
        .unwrap()
        .into_iter()
        .find(|g| g.uuid == target)
        .unwrap();
    assert_eq!(g.icon_id, 48);

    let (reopened, _tmp) = save_and_reopen(&vault, "test-basic-002");
    let g2 = reopened
        .list_groups()
        .unwrap()
        .into_iter()
        .find(|g| g.uuid == target)
        .unwrap();
    assert_eq!(g2.icon_id, 48);
}

#[test]
fn update_group_custom_icon_uuid_sets_value() {
    let vault = open_basic();
    let target = group_uuid(&vault, "Personal");
    let icon_uuid = vault.add_custom_icon(vec![1, 2, 3, 4]).expect("icon");

    let mut patch = GroupPatch::empty();
    patch.custom_icon_uuid = Some(icon_uuid.clone());
    vault.update_group(target.clone(), patch).expect("update");

    let g = vault
        .list_groups()
        .unwrap()
        .into_iter()
        .find(|g| g.uuid == target)
        .unwrap();
    assert_eq!(g.custom_icon_uuid, Some(icon_uuid));
}

#[test]
fn clear_group_custom_icon_returns_to_none() {
    let vault = open_basic();
    let target = group_uuid(&vault, "Personal");
    let icon_uuid = vault.add_custom_icon(vec![1, 2, 3, 4]).expect("icon");

    let mut patch = GroupPatch::empty();
    patch.custom_icon_uuid = Some(icon_uuid);
    vault.update_group(target.clone(), patch).unwrap();
    assert!(
        vault
            .list_groups()
            .unwrap()
            .iter()
            .find(|g| g.uuid == target)
            .unwrap()
            .custom_icon_uuid
            .is_some()
    );

    vault
        .clear_group_custom_icon(target.clone())
        .expect("clear");
    assert!(
        vault
            .list_groups()
            .unwrap()
            .iter()
            .find(|g| g.uuid == target)
            .unwrap()
            .custom_icon_uuid
            .is_none()
    );
}

#[test]
fn update_group_with_none_icon_fields_leaves_existing_alone() {
    let vault = open_basic();
    let target = group_uuid(&vault, "Personal");

    // Seed an icon.
    let mut seed = GroupPatch::empty();
    seed.icon_id = Some(42);
    vault.update_group(target.clone(), seed).unwrap();

    // Patch only the name; icon should survive.
    let mut renamed = GroupPatch::empty();
    renamed.name = Some("Renamed".to_owned());
    vault.update_group(target.clone(), renamed).unwrap();

    let g = vault
        .list_groups()
        .unwrap()
        .into_iter()
        .find(|g| g.uuid == target)
        .unwrap();
    assert_eq!(g.name, "Renamed");
    assert_eq!(g.icon_id, 42);
}

#[test]
fn clear_group_custom_icon_with_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .clear_group_custom_icon(BOGUS.to_owned())
        .expect_err("bogus uuid");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn update_group_with_bogus_custom_icon_uuid_returns_not_found() {
    let vault = open_basic();
    let target = group_uuid(&vault, "Personal");
    let mut patch = GroupPatch::empty();
    patch.custom_icon_uuid = Some("not-a-uuid".to_owned());
    let err = vault
        .update_group(target, patch)
        .expect_err("malformed uuid");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn delete_group_removes_it_and_persists() {
    let vault = open_basic();
    // Create a fresh subgroup to delete (don't kill Personal/Work).
    let parent = group_uuid(&vault, "Personal");
    let target = vault
        .create_group("Throwaway".to_owned(), Some(parent))
        .expect("create");

    vault.delete_group(target.clone()).expect("delete");
    assert!(
        vault
            .list_groups()
            .unwrap()
            .iter()
            .all(|g| g.uuid != target),
        "deleted in memory",
    );

    let (reopened, _tmp) = save_and_reopen(&vault, "test-basic-002");
    assert!(
        reopened
            .list_groups()
            .unwrap()
            .iter()
            .all(|g| g.uuid != target),
        "deleted after reopen",
    );
}

#[test]
fn move_group_to_new_parent() {
    let vault = open_basic();
    let work = group_uuid(&vault, "Work");
    let parent = group_uuid(&vault, "Personal");
    let moving = vault
        .create_group("Movable".to_owned(), Some(parent.clone()))
        .expect("create");

    vault
        .move_group(moving.clone(), work.clone())
        .expect("move");

    let groups = vault.list_groups().expect("list");
    let g = groups.iter().find(|g| g.uuid == moving).unwrap();
    assert_eq!(g.parent_uuid.as_deref(), Some(work.as_str()));
}

#[test]
fn move_group_into_self_returns_not_found_via_circular_move() {
    let vault = open_basic();
    let parent = group_uuid(&vault, "Personal");
    let outer = vault
        .create_group("Outer".to_owned(), Some(parent))
        .expect("create outer");
    let inner = vault
        .create_group("Inner".to_owned(), Some(outer.clone()))
        .expect("create inner");

    // Moving Outer into Inner is a cycle.
    let err = vault
        .move_group(outer, inner)
        .expect_err("cycle should fail");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn delete_group_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .delete_group(BOGUS.to_owned())
        .expect_err("bogus should miss");
    assert!(matches!(err, VaultError::NotFound));
}

// =======================================================================
// Recycle bin
// =======================================================================

#[test]
fn recycle_entry_returns_bin_uuid_when_enabled() {
    let vault = open_recycle();
    // The recycle fixture's meta state isn't a guaranteed contract;
    // explicitly enable the bin and seed its group ourselves so the
    // test is independent of the fixture's recycle_bin_enabled flag.
    let bin_group = vault
        .create_group("BinGroup".to_owned(), Some(root_uuid(&vault)))
        .expect("create bin group");
    vault
        .set_recycle_bin(true, Some(bin_group.clone()))
        .expect("enable bin");

    let target_group = vault
        .create_group("Holder".to_owned(), Some(root_uuid(&vault)))
        .expect("create holder");
    let new_uuid = vault
        .create_entry(EntryCreate::new("To Recycle", target_group))
        .expect("create");

    let bin = vault
        .recycle_entry(new_uuid.clone())
        .expect("recycle")
        .expect("bin enabled — Some(uuid)");
    assert_eq!(bin, bin_group);
}

#[test]
fn recycle_entry_falls_through_to_hard_delete_when_disabled() {
    let vault = open_basic();
    // basic fixture has the recycle bin disabled by default; verify
    // and exercise the fall-through.
    vault
        .set_recycle_bin(false, None)
        .expect("disable recycle bin");
    let new_uuid = vault
        .create_entry(EntryCreate::new("Doomed", group_uuid(&vault, "Work")))
        .expect("create");

    let result = vault.recycle_entry(new_uuid.clone()).expect("recycle");
    assert!(result.is_none(), "disabled bin → None (hard-delete)");
    assert!(
        vault
            .list_entries(None)
            .unwrap()
            .iter()
            .all(|e| e.uuid != new_uuid),
        "entry is gone after disabled-bin recycle",
    );
}

#[test]
fn recycle_group_round_trip() {
    let vault = open_recycle();
    let bin_group = vault
        .create_group("BinGroup".to_owned(), Some(root_uuid(&vault)))
        .expect("create bin group");
    vault
        .set_recycle_bin(true, Some(bin_group.clone()))
        .expect("enable bin");

    let target = vault
        .create_group("ToRecycle".to_owned(), Some(root_uuid(&vault)))
        .expect("create");
    let bin = vault
        .recycle_group(target.clone())
        .expect("recycle")
        .expect("bin enabled");
    assert_eq!(bin, bin_group);
    let groups = vault.list_groups().unwrap();
    let recycled = groups.iter().find(|g| g.uuid == target).unwrap();
    assert_eq!(recycled.parent_uuid.as_deref(), Some(bin.as_str()));
}

#[test]
fn empty_recycle_bin_returns_count_and_clears() {
    let vault = open_recycle();
    let count_before = vault.empty_recycle_bin().expect("empty");
    // The fixture has 3 entries pre-populated in the bin scenario;
    // exact count depends on the fixture sidecar but must be > 0.
    assert!(count_before >= 1, "fixture has populated bin");

    let count_again = vault.empty_recycle_bin().expect("empty again");
    assert_eq!(count_again, 0, "second empty is a no-op");
}

#[test]
fn set_recycle_bin_round_trips_disabled_with_group() {
    let vault = open_basic();
    let bin = vault
        .create_group("Bin".to_owned(), Some(root_uuid(&vault)))
        .expect("create bin");

    // Disable but keep the group reference — the round-trip should
    // preserve both pieces of state.
    vault
        .set_recycle_bin(false, Some(bin.clone()))
        .expect("set");
    let (reopened, _tmp) = save_and_reopen(&vault, "test-basic-002");
    // We can't directly inspect meta; instead, re-enable in the
    // reopened vault and verify recycle_entry uses our bin.
    reopened
        .set_recycle_bin(true, Some(bin.clone()))
        .expect("re-enable");
    let new_uuid = reopened
        .create_entry(EntryCreate::new("Bin-bound", group_uuid(&reopened, "Work")))
        .expect("create");
    let used_bin = reopened
        .recycle_entry(new_uuid)
        .expect("recycle")
        .expect("bin enabled");
    assert_eq!(used_bin, bin, "set_recycle_bin's group survived the reopen");
}

#[test]
fn set_recycle_bin_bogus_group_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .set_recycle_bin(true, Some(BOGUS.to_owned()))
        .expect_err("bogus should miss");
    assert!(matches!(err, VaultError::NotFound));
}

// =======================================================================
// Meta setters
// =======================================================================

#[test]
fn meta_setters_round_trip_through_save() {
    let vault = open_basic();
    vault
        .set_database_name("Renamed Vault".to_owned())
        .expect("name");
    vault
        .set_database_description("New description.".to_owned())
        .expect("description");
    vault
        .set_default_username("default-user".to_owned())
        .expect("default username");
    vault.set_color("#ff8800".to_owned()).expect("color");

    // No public read API for meta yet — round-trip through
    // save_to_bytes + reopen and re-set the same values
    // (idempotent setter; this exercises the write path at least).
    let (reopened, _tmp) = save_and_reopen(&vault, "test-basic-002");
    reopened
        .set_database_name("Renamed Vault".to_owned())
        .expect("re-set after reopen");
}

#[test]
fn set_color_passes_non_canonical_strings_through() {
    let vault = open_basic();
    // Non-canonical inputs (named colour, lowercase hex, "#RGB")
    // round-trip — the facade doesn't gatekeep.
    vault.set_color("rebeccapurple".to_owned()).expect("named");
    vault.set_color("#0F0".to_owned()).expect("short hex");
    vault.set_color(String::new()).expect("empty");
}

// =======================================================================
// Custom icons
// =======================================================================

#[test]
fn add_custom_icon_round_trips_bytes() {
    let vault = open_basic();
    let bytes: Vec<u8> = (0u8..=63).collect();
    let id = vault.add_custom_icon(bytes.clone()).expect("add");
    let got = vault.custom_icon(id).expect("get").expect("icon present");
    assert_eq!(got, bytes);
}

#[test]
fn unreferenced_custom_icon_is_gc_d_at_save() {
    // keepass-core's save pipeline GCs custom icons that aren't
    // referenced by any entry or group. Slice 6 doesn't yet expose
    // an `entry.set_custom_icon` setter, so an icon added by the
    // FFI is always orphan and won't survive a save-reopen until
    // a later slice wires up the assignment side. This test pins
    // the current behaviour explicitly.
    let vault = open_basic();
    let id = vault.add_custom_icon(b"PNG-ish".to_vec()).expect("add");
    // Visible in-memory before save.
    assert!(vault.custom_icon(id.clone()).expect("get").is_some());
    let (reopened, _tmp) = save_and_reopen(&vault, "test-basic-002");
    // Gone after save: orphan icons get pruned by `gc_custom_icons_pool`.
    assert!(reopened.custom_icon(id).expect("get").is_none());
}

#[test]
fn remove_custom_icon_returns_true_then_false() {
    let vault = open_basic();
    let id = vault.add_custom_icon(vec![1, 2, 3]).expect("add");
    assert!(vault.remove_custom_icon(id.clone()).expect("first"));
    assert!(!vault.remove_custom_icon(id).expect("second"));
}

#[test]
fn custom_icon_unknown_uuid_returns_none() {
    let vault = open_basic();
    assert!(vault.custom_icon(BOGUS.to_owned()).expect("get").is_none());
}

#[test]
fn custom_icon_unparseable_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .custom_icon("not-a-uuid".to_owned())
        .expect_err("unparseable should miss");
    assert!(matches!(err, VaultError::NotFound));
}

// =======================================================================
// Locked-after-lock
// =======================================================================

#[test]
fn slice6_methods_return_locked_after_lock() {
    let vault = open_basic();
    let some_group = group_uuid(&vault, "Personal");
    vault.lock().expect("lock");

    assert!(matches!(
        vault.create_group("x".to_owned(), None),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.update_group(some_group.clone(), GroupPatch::empty()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.delete_group(some_group.clone()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.move_group(some_group.clone(), some_group.clone()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.clear_group_custom_icon(some_group.clone()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.recycle_entry(BOGUS.to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.recycle_group(BOGUS.to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(vault.empty_recycle_bin(), Err(VaultError::Locked)));
    assert!(matches!(
        vault.set_recycle_bin(true, None),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.set_database_name("x".to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.set_database_description("x".to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.set_default_username("x".to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.set_color("#fff".to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.add_custom_icon(vec![]),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.remove_custom_icon(BOGUS.to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.custom_icon(BOGUS.to_owned()),
        Err(VaultError::Locked)
    ));
}
