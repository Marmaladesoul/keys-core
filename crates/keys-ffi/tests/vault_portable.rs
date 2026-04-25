//! Integration tests for slice 8 — cross-vault export/import via the
//! opaque `PortableEntry` carrier.

use std::path::PathBuf;
use std::sync::Arc;

use keys_ffi::{Vault, VaultError};

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
    .expect("open basic")
}

fn open_custom() -> Arc<Vault> {
    Vault::new(
        fixture("pykeepass/custom-fields.kdbx"),
        "test-custom-104".to_owned(),
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
    let src_protected: Vec<_> = src_entry
        .protected_fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    let imp_protected: Vec<_> = imported
        .protected_fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(src_protected, imp_protected);

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
        "test-deep-006".to_owned(),
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
