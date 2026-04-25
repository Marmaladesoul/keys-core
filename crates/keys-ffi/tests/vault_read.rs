//! Integration tests for slice 3 — read surface.

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

fn open_basic() -> std::sync::Arc<Vault> {
    Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "test-basic-002".to_owned(),
    )
    .expect("kdbx3-basic should open")
}

#[test]
fn list_entries_none_returns_all() {
    let vault = open_basic();
    let entries = vault.list_entries(None).expect("list");
    // Sidecar declares 6 entries in this fixture.
    assert_eq!(entries.len(), 6);
    let titles: Vec<_> = entries.iter().map(|e| e.title.as_str()).collect();
    assert!(titles.contains(&"Acme Banking"));
    assert!(titles.contains(&"Fabrikam VPN"));
}

#[test]
fn list_entries_some_is_direct_children_only() {
    let vault = open_basic();
    let groups = vault.list_groups().expect("groups");
    let personal = groups
        .iter()
        .find(|g| g.name == "Personal")
        .expect("Personal group present");
    let entries = vault
        .list_entries(Some(personal.uuid.clone()))
        .expect("list scoped");
    // Personal has 3 direct entries per the sidecar.
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|e| e.group_uuid == personal.uuid));
}

#[test]
fn list_entries_with_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .list_entries(Some("00000000-0000-0000-0000-000000000000".to_owned()))
        .expect_err("bogus group uuid should fail");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn list_entries_with_invalid_uuid_string_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .list_entries(Some("not-a-uuid".to_owned()))
        .expect_err("invalid uuid string should fail");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn list_groups_includes_root_and_named_groups() {
    let vault = open_basic();
    let groups = vault.list_groups().expect("groups");
    assert!(!groups.is_empty());

    let roots: Vec<_> = groups.iter().filter(|g| g.parent_uuid.is_none()).collect();
    assert_eq!(roots.len(), 1, "exactly one root group");

    assert!(groups.iter().any(|g| g.name == "Personal"));
    assert!(groups.iter().any(|g| g.name == "Work"));
}

#[test]
fn list_groups_parent_child_consistent() {
    let vault = open_basic();
    let groups = vault.list_groups().expect("groups");
    let root = groups
        .iter()
        .find(|g| g.parent_uuid.is_none())
        .expect("root present");
    // Root's child_group_uuids should reference Personal + Work.
    assert_eq!(root.child_group_uuids.len(), 2);
    for child_uuid in &root.child_group_uuids {
        let child = groups
            .iter()
            .find(|g| &g.uuid == child_uuid)
            .expect("child resolves");
        assert_eq!(child.parent_uuid.as_ref(), Some(&root.uuid));
    }
}

#[test]
fn get_entry_round_trips_basic_fields() {
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let target = summaries
        .iter()
        .find(|e| e.title == "Acme Banking")
        .expect("Acme Banking present");

    let entry = vault.get_entry(target.uuid.clone()).expect("get");
    assert_eq!(entry.title, "Acme Banking");
    assert_eq!(entry.username, "dave@example.net");
    assert_eq!(entry.url, "https://bank.acme.example");
    assert_eq!(entry.uuid, target.uuid);
    assert_eq!(entry.group_uuid, target.group_uuid);
}

#[test]
fn get_entry_with_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .get_entry("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus entry uuid should fail");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn get_entry_password_appears_as_protected_field_with_no_value() {
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let entry = vault
        .get_entry(summaries[0].uuid.clone())
        .expect("get first entry");

    let password = entry
        .protected_fields
        .iter()
        .find(|f| f.name == "Password")
        .expect("Password is a protected field");
    assert!(!password.revealed);
    assert!(password.value.is_none(), "no plaintext crosses boundary");
}

#[test]
fn protected_custom_fields_partition_correctly() {
    let vault = Vault::new(
        fixture("pykeepass/custom-fields.kdbx"),
        "test-custom-104".to_owned(),
    )
    .expect("custom-fields fixture should open");
    let summaries = vault.list_entries(None).expect("list");
    assert_eq!(summaries.len(), 1, "fixture has one entry");

    let entry = vault.get_entry(summaries[0].uuid.clone()).expect("get");

    // Sidecar: API Secret + PIN are protected; API Key ID + Recovery Code aren't.
    // Plus the always-protected Password slot.
    let custom_names: Vec<_> = entry
        .custom_fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert!(custom_names.contains(&"API Key ID"));
    assert!(custom_names.contains(&"Recovery Code"));

    let protected_names: Vec<_> = entry
        .protected_fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert!(protected_names.contains(&"Password"));
    assert!(protected_names.contains(&"API Secret"));
    assert!(protected_names.contains(&"PIN"));

    for f in &entry.protected_fields {
        assert!(!f.revealed);
        assert!(f.value.is_none(), "no plaintext crosses boundary");
    }
}

#[test]
fn search_is_case_insensitive_substring() {
    let vault = open_basic();
    let hits = vault.search("acme".to_owned()).expect("search");
    let titles: Vec<_> = hits.iter().map(|e| e.title.as_str()).collect();
    assert!(titles.contains(&"Acme Banking"));
    assert!(titles.contains(&"Acme Cloud"));
    assert!(!titles.contains(&"Fabrikam VPN"));
}

#[test]
fn search_matches_url() {
    let vault = open_basic();
    let hits = vault.search("FABRIKAM".to_owned()).expect("search");
    assert!(hits.iter().any(|e| e.title == "Fabrikam VPN"));
}

#[test]
fn search_empty_query_returns_no_hits() {
    let vault = open_basic();
    let hits = vault.search(String::new()).expect("search");
    assert!(hits.is_empty());
}

#[test]
fn read_methods_return_locked_after_lock() {
    let vault = open_basic();
    vault.lock().expect("lock");

    assert!(matches!(vault.list_entries(None), Err(VaultError::Locked)));
    assert!(matches!(vault.list_groups(), Err(VaultError::Locked)));
    assert!(matches!(
        vault.get_entry("00000000-0000-0000-0000-000000000000".to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.search("anything".to_owned()),
        Err(VaultError::Locked)
    ));
}
