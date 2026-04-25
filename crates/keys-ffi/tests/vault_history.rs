//! Integration tests for slice 8 — history viewing, restore, and
//! delete-at-index.

use std::path::PathBuf;
use std::sync::Arc;

use keys_ffi::{EntryPatch, Vault, VaultError};

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
    .expect("open")
}

/// Mutate `vault`'s first entry n times to seed history snapshots.
/// Returns the entry's UUID.
fn seed_history(vault: &Vault, n: usize) -> String {
    let summaries = vault.list_entries(None).expect("list");
    let uuid = summaries[0].uuid.clone();
    for i in 0..n {
        let mut patch = EntryPatch::empty();
        patch.title = Some(format!("Snapshot {i}"));
        vault
            .update_entry(uuid.clone(), patch)
            .expect("update for history");
    }
    uuid
}

#[test]
fn entry_history_lists_oldest_first() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 3);
    let history = vault.entry_history(uuid.clone()).expect("history");
    assert_eq!(history.len(), 3);
    assert!(history[0].modified_ms <= history[1].modified_ms);
    assert!(history[1].modified_ms <= history[2].modified_ms);
}

#[test]
fn history_record_carries_protected_field_names_no_plaintext() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 1);
    let history = vault.entry_history(uuid).expect("history");
    let record = &history[0];
    assert!(
        record
            .protected_field_names
            .contains(&"Password".to_owned())
    );
    // No plaintext-bearing field on HistoryRecord — slot doesn't exist
    // by design. Test passes structurally.
}

#[test]
fn entry_history_bogus_uuid_returns_not_found() {
    let vault = open_basic();
    let err = vault
        .entry_history("00000000-0000-0000-0000-000000000000".to_owned())
        .expect_err("bogus uuid");
    assert!(matches!(err, VaultError::NotFound));
}

#[test]
fn restore_brings_entry_back_to_snapshot_state() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 2);

    let history_before = vault.entry_history(uuid.clone()).expect("history");
    let target_title = history_before[0].title.clone();

    vault
        .restore_entry_from_history(uuid.clone(), 0)
        .expect("restore");

    let entry = vault.get_entry(uuid).expect("get after restore");
    assert_eq!(entry.title, target_title);
}

#[test]
fn restore_appends_pre_restore_snapshot_for_undoability() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 2);
    let count_before = vault.entry_history(uuid.clone()).unwrap().len();

    vault
        .restore_entry_from_history(uuid.clone(), 0)
        .expect("restore");

    // History grew by one (the pre-restore live state was snapshotted).
    let count_after = vault.entry_history(uuid).unwrap().len();
    assert_eq!(count_after, count_before + 1);
}

#[test]
fn restore_out_of_range_returns_index_out_of_range() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 1);
    let err = vault
        .restore_entry_from_history(uuid, 999)
        .expect_err("out of range");
    assert!(matches!(err, VaultError::IndexOutOfRange), "got {err:?}");
}

#[test]
fn delete_history_removes_record_at_index() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 3);
    let before = vault.entry_history(uuid.clone()).unwrap();
    let target_title = before[1].title.clone();

    vault.delete_history_at(uuid.clone(), 1).expect("delete");

    let after = vault.entry_history(uuid).unwrap();
    assert_eq!(after.len(), before.len() - 1);
    // `seed_history` produces unique titles per snapshot, so title is
    // a stable identity here (modified_ms can collide at ms precision).
    assert!(
        after.iter().all(|r| r.title != target_title),
        "removed record's title is gone",
    );
}

#[test]
fn delete_history_out_of_range_returns_index_out_of_range() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 1);
    let err = vault.delete_history_at(uuid, 42).expect_err("out of range");
    assert!(matches!(err, VaultError::IndexOutOfRange));
}

#[test]
fn history_methods_return_locked_after_lock() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 1);
    vault.lock().expect("lock");
    assert!(matches!(
        vault.entry_history(uuid.clone()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.restore_entry_from_history(uuid.clone(), 0),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.delete_history_at(uuid, 0),
        Err(VaultError::Locked)
    ));
}
