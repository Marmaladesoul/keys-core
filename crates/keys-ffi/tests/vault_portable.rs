//! Integration tests for slice 8 — cross-vault export/import via the
//! opaque `PortableEntry` carrier.

use std::sync::Arc;

use keys_ffi::{Vault, VaultError};

mod common;
use common::fixture;

fn open_basic() -> Arc<Vault> {
    Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("open basic")
}

fn open_custom() -> Arc<Vault> {
    Vault::new(
        fixture("pykeepass/custom-fields.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("open custom-fields")
}

fn root_uuid(vault: &Vault) -> String {
    vault
        .list_groups()
        .unwrap()
        .into_iter()
        .find(|g| g.parent_uuid.is_none())
        .unwrap()
        .uuid
}

#[test]
fn export_then_import_into_different_vault_preserves_basic_fields() {
    let src = open_custom();
    let dst = open_basic();

    let summaries = src.list_entries(None).expect("list src");
    let src_entry = src.get_entry(summaries[0].uuid.clone()).expect("get src");

    let portable = src.export_entry(src_entry.uuid.clone()).expect("export");
    let new_uuid = dst.import_entry(portable, root_uuid(&dst)).expect("import");

    let imported = dst.get_entry(new_uuid).expect("get imported");
    assert_eq!(imported.title, src_entry.title);
    assert_eq!(imported.username, src_entry.username);
    assert_eq!(imported.url, src_entry.url);
    // Imports get freshly-minted UUIDs so cross-vault duplication
    // doesn't trip merge-side conflict logic.
    assert_ne!(imported.uuid, src_entry.uuid);
}

#[test]
fn import_preserves_protected_field_structure() {
    let src = open_custom();
    let dst = open_basic();

    let src_uuid = src.list_entries(None).unwrap()[0].uuid.clone();
    let portable = src.export_entry(src_uuid.clone()).expect("export");
    let new_uuid = dst.import_entry(portable, root_uuid(&dst)).expect("import");

    let imported = dst.get_entry(new_uuid.clone()).expect("get imported");
    let src_entry = src.get_entry(src_uuid.clone()).unwrap();
    // Compare the union of password slot + custom protected field
    // names. Protected custom fields now surface inside
    // `custom_fields` with `is_protected = true`; Password is its
    // own singleton slot via `password_field`.
    let protected_names = |e: &keys_ffi::Entry| -> Vec<String> {
        let mut names = vec![e.password_field.name.clone()];
        names.extend(
            e.custom_fields
                .iter()
                .filter(|c| c.is_protected)
                .map(|c| c.name.clone()),
        );
        names
    };
    assert_eq!(protected_names(&src_entry), protected_names(&imported));

    // Reveal carries protected plaintext through the round-trip.
    let src_pw = src.reveal_field(src_uuid, "Password".to_owned()).unwrap();
    let imp_pw = dst.reveal_field(new_uuid, "Password".to_owned()).unwrap();
    assert_eq!(src_pw, imp_pw, "Password plaintext survives export+import");
}

#[test]
fn portable_carrier_is_single_use() {
    let src = open_custom();
    let dst = open_basic();
    let dst2 = Vault::new(
        fixture("keepassxc/kdbx3-deep-groups.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("open deep-groups");

    let src_uuid = src.list_entries(None).unwrap()[0].uuid.clone();
    let portable = src.export_entry(src_uuid).expect("export");

    // First import succeeds.
    dst.import_entry(portable.clone(), root_uuid(&dst))
        .expect("first import");

    // Second import on the same handle returns NotFound (the inner
    // PortableEntry has been taken).
    let err = dst2
        .import_entry(portable, root_uuid(&dst2))
        .expect_err("second import should fail");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn export_bogus_uuid_returns_not_found() {
    let src = open_basic();
    let err = src
        .export_entry("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus uuid");
    assert!(matches!(err, VaultError::NotFound));
}

#[test]
fn import_bogus_group_returns_not_found() {
    let src = open_basic();
    let dst = open_basic();
    let any_uuid = src.list_entries(None).unwrap()[0].uuid.clone();
    let portable = src.export_entry(any_uuid).expect("export");
    let err = dst
        .import_entry(portable, "00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus group");
    assert!(matches!(err, VaultError::NotFound));
}

#[test]
fn portable_methods_return_locked_after_lock() {
    let src = open_basic();
    let dst = open_basic();
    let any_uuid = src.list_entries(None).unwrap()[0].uuid.clone();

    src.lock().expect("lock src");
    assert!(matches!(
        src.export_entry(any_uuid.clone()),
        Err(VaultError::Locked)
    ));

    let portable = open_basic().export_entry(any_uuid).expect("fresh export");
    dst.lock().expect("lock dst");
    assert!(matches!(
        dst.import_entry(portable, root_uuid(&open_basic())),
        Err(VaultError::Locked)
    ));
}

// ---------------------------------------------------------------------
// import_entry_with_uuid (FFI bridge for keepass-core PR #136)
// ---------------------------------------------------------------------

#[test]
fn import_entry_with_uuid_restores_caller_supplied_uuid() {
    let src = open_basic();
    let dst = open_basic();

    // Pick an existing entry from src and capture its UUID.
    let original_uuid = src.list_entries(None).unwrap()[0].uuid.clone();
    let portable = src.export_entry(original_uuid.clone()).expect("export");

    // Both vaults opened the same fixture, so the UUID is live in dst
    // too. Delete it first to free the UUID — the matching tombstone
    // is what import_entry_with_uuid clears as part of the operation.
    dst.delete_entry(original_uuid.clone())
        .expect("delete dst-side");

    let restored = dst
        .import_entry_with_uuid(portable, root_uuid(&dst), original_uuid.clone())
        .expect("import with uuid");
    assert_eq!(restored, original_uuid, "method must return target_uuid");

    let got = dst.get_entry(original_uuid.clone()).expect("get entry");
    assert_eq!(got.uuid, original_uuid);
}

#[test]
fn import_entry_with_uuid_bogus_target_returns_not_found() {
    let src = open_basic();
    let dst = open_basic();
    let original_uuid = src.list_entries(None).unwrap()[0].uuid.clone();
    let portable = src.export_entry(original_uuid).expect("export");

    let err = dst
        .import_entry_with_uuid(portable, root_uuid(&dst), "not-a-uuid".to_owned())
        .expect_err("bogus target uuid");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn import_entry_with_uuid_bogus_group_returns_not_found() {
    let src = open_basic();
    let dst = open_basic();
    let original_uuid = src.list_entries(None).unwrap()[0].uuid.clone();
    let portable = src.export_entry(original_uuid.clone()).expect("export");

    let err = dst
        .import_entry_with_uuid(
            portable,
            "00000000-0000-0000-0000-000000000000".to_owned(),
            original_uuid,
        )
        .expect_err("bogus group");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn import_entry_with_uuid_returns_locked_after_lock() {
    let src = open_basic();
    let dst = open_basic();
    let original_uuid = src.list_entries(None).unwrap()[0].uuid.clone();
    let portable = src.export_entry(original_uuid.clone()).expect("export");

    dst.lock().expect("lock");
    let err = dst
        .import_entry_with_uuid(portable, root_uuid(&open_basic()), original_uuid)
        .expect_err("locked");
    assert!(matches!(err, VaultError::Locked), "got {err:?}");
}
