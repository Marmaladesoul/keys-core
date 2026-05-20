//! Integration tests for slice 8 — history viewing, restore, and
//! delete-at-index.

#![allow(clippy::cast_possible_truncation)]

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
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
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
fn history_record_surfaces_full_entry_shape() {
    // Slice 8B — HistoryRecord enrichment. Each snapshot now mirrors
    // Entry's read surface (sans uuid/group_uuid/password plaintext).
    // Mutate a richly-populated entry; the pre-mutation snapshot
    // should carry the full pre-mutation field set.
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let uuid = summaries[0].uuid.clone();

    // Seed: populate URL, notes, tags, a non-protected custom field.
    let mut seed = EntryPatch::empty();
    seed.url = Some("https://pre-edit.example".to_owned());
    seed.notes = Some("snapshot-test pre-edit notes".to_owned());
    seed.tags = Some(vec!["alpha".to_owned(), "beta".to_owned()]);
    seed.custom_fields = Some(vec![keys_ffi::CustomField::new(
        "ProjectCode",
        "PRE-EDIT-VALUE",
    )]);
    vault.update_entry(uuid.clone(), seed).expect("seed update");

    // Mutate so the seed-state is pushed into history.
    let mut bump = EntryPatch::empty();
    bump.title = Some("post-edit title".to_owned());
    vault.update_entry(uuid.clone(), bump).expect("bump");

    let history = vault.entry_history(uuid).expect("history");
    let snap = history.last().expect("at least one snapshot");

    assert_eq!(snap.url, "https://pre-edit.example");
    assert_eq!(snap.notes, "snapshot-test pre-edit notes");
    assert_eq!(snap.tags, vec!["alpha".to_owned(), "beta".to_owned()]);
    let project = snap
        .custom_fields
        .iter()
        .find(|f| f.name == "ProjectCode")
        .expect("custom field present on snapshot");
    assert!(!project.is_protected);
    assert_eq!(project.value, "PRE-EDIT-VALUE");

    // created_ms is preserved across snapshots; last_access_ms exposed.
    assert!(snap.created_ms > 0);
    assert!(snap.modified_ms > 0);
}

#[test]
fn history_record_protected_custom_field_carries_no_plaintext() {
    // Slice 8B — a protected custom field on the snapshot should
    // surface with `is_protected = true` and an empty `value`. Plain-
    // text never crosses the FFI boundary at history-list time.
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let uuid = summaries[0].uuid.clone();

    // Seed: add a protected custom field via setProtectedField (the
    // canonical path; updateEntry's CustomField list excludes
    // protected by design).
    vault
        .set_protected_field(
            uuid.clone(),
            "Recovery".to_owned(),
            "secret-recovery-code".to_owned(),
        )
        .expect("set protected");

    // Mutate so the seed state is in history.
    let mut bump = EntryPatch::empty();
    bump.title = Some("post-protected-seed".to_owned());
    vault.update_entry(uuid.clone(), bump).expect("bump");

    let history = vault.entry_history(uuid).expect("history");
    let snap = history.last().expect("snapshot");

    let recovery = snap
        .custom_fields
        .iter()
        .find(|f| f.name == "Recovery")
        .expect("protected custom field present");
    assert!(recovery.is_protected);
    assert_eq!(recovery.value, "", "no plaintext at history-list time");
    assert!(snap.protected_field_names.contains(&"Recovery".to_owned()));
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
        vault.delete_history_at(uuid.clone(), 0),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.reveal_history_field(uuid.clone(), 0, "Password".to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.entry_history_attachment_bytes(uuid, 0, "any".to_owned()),
        Err(VaultError::Locked)
    ));
}

// MARK: - Slice 8C-tail: reveal_history_field + entry_history_attachment_bytes

#[test]
fn reveal_history_field_returns_pre_edit_password() {
    // Slice 8C-tail — no-restore reveal of a historical protected
    // field. Seed: change the password; the pre-edit password is
    // captured in history[0].
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let uuid = summaries[0].uuid.clone();

    vault
        .set_protected_field(
            uuid.clone(),
            "Password".to_owned(),
            "history-era-password".to_owned(),
        )
        .expect("seed pre-edit password");

    vault
        .set_protected_field(
            uuid.clone(),
            "Password".to_owned(),
            "current-password".to_owned(),
        )
        .expect("bump to current password");

    let history = vault.entry_history(uuid.clone()).expect("history");
    let pre_edit_index = (history.len() - 1) as u32;

    let revealed = vault
        .reveal_history_field(uuid, pre_edit_index, "Password".to_owned())
        .expect("reveal historical password");
    assert_eq!(revealed, "history-era-password");
}

#[test]
fn reveal_history_field_returns_pre_edit_protected_custom_field() {
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let uuid = summaries[0].uuid.clone();

    vault
        .set_protected_field(
            uuid.clone(),
            "Recovery".to_owned(),
            "old-recovery-code".to_owned(),
        )
        .expect("seed recovery");

    // Mutate via update_entry so the seed-state snapshot lands in history.
    let mut bump = EntryPatch::empty();
    bump.title = Some("bump for snapshot".to_owned());
    vault.update_entry(uuid.clone(), bump).expect("bump");

    vault
        .set_protected_field(
            uuid.clone(),
            "Recovery".to_owned(),
            "new-recovery-code".to_owned(),
        )
        .expect("rotate recovery");

    let history = vault.entry_history(uuid.clone()).expect("history");
    // The earliest snapshot bearing "Recovery" is where we seeded it.
    let snapshot_index = history
        .iter()
        .position(|h| h.protected_field_names.contains(&"Recovery".to_owned()))
        .expect("snapshot with recovery present") as u32;

    let revealed = vault
        .reveal_history_field(uuid, snapshot_index, "Recovery".to_owned())
        .expect("reveal historical recovery");
    assert_eq!(revealed, "old-recovery-code");
}

#[test]
fn reveal_history_field_unknown_field_returns_field_not_found() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 1);
    let err = vault
        .reveal_history_field(uuid, 0, "Nonexistent".to_owned())
        .expect_err("unknown field");
    assert!(matches!(err, VaultError::FieldNotFound), "got {err:?}");
}

#[test]
fn reveal_history_field_out_of_range_returns_index_out_of_range() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 1);
    let err = vault
        .reveal_history_field(uuid, 999, "Password".to_owned())
        .expect_err("out of range");
    assert!(matches!(err, VaultError::IndexOutOfRange), "got {err:?}");
}

#[test]
fn entry_history_attachment_bytes_returns_pre_edit_payload() {
    // Seed: attach payload B0 named "doc.txt"; snapshot via patch
    // mutation; replace attachment with payload B1 under same name.
    // Historical fetch returns B0; current returns B1.
    let vault = open_basic();
    let summaries = vault.list_entries(None).expect("list");
    let uuid = summaries[0].uuid.clone();

    let b0: Vec<u8> = b"historical-payload-v0".to_vec();
    let b1: Vec<u8> = b"current-payload-v1".to_vec();

    vault
        .add_entry_attachment(uuid.clone(), "doc.txt".to_owned(), b0.clone())
        .expect("seed b0");

    // Snapshot the seed state via a benign mutation.
    let mut bump = EntryPatch::empty();
    bump.title = Some("snapshot pivot".to_owned());
    vault.update_entry(uuid.clone(), bump).expect("bump");

    // Replace the attachment payload (add_entry_attachment is
    // idempotent-by-name).
    vault
        .add_entry_attachment(uuid.clone(), "doc.txt".to_owned(), b1.clone())
        .expect("replace with b1");

    // Current path returns the new bytes.
    let current = vault
        .entry_attachment_bytes(uuid.clone(), "doc.txt".to_owned())
        .expect("current bytes");
    assert_eq!(current, b1);

    // Historical path returns the seeded bytes.
    let history = vault.entry_history(uuid.clone()).expect("history");
    let pre_edit_index = history
        .iter()
        .position(|h| h.attachments.iter().any(|a| a.name == "doc.txt"))
        .expect("snapshot with attachment present") as u32;

    let historical = vault
        .entry_history_attachment_bytes(uuid, pre_edit_index, "doc.txt".to_owned())
        .expect("historical bytes");
    assert_eq!(historical, b0);
}

#[test]
fn entry_history_attachment_bytes_unknown_name_returns_not_found() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 1);
    let err = vault
        .entry_history_attachment_bytes(uuid, 0, "missing.txt".to_owned())
        .expect_err("unknown name");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn entry_history_attachment_bytes_out_of_range_returns_index_out_of_range() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 1);
    let err = vault
        .entry_history_attachment_bytes(uuid, 999, "any".to_owned())
        .expect_err("out of range");
    assert!(matches!(err, VaultError::IndexOutOfRange), "got {err:?}");
}

// MARK: - Slice 8I-F-B: trim_entry_history

#[test]
fn vault_trim_entry_history_applies_current_limits() {
    let vault = open_basic();
    // Seed plenty of history snapshots, then tighten the max-items
    // policy so trimming has work to do.
    let uuid = seed_history(&vault, 6);
    let before = vault.entry_history(uuid.clone()).expect("history").len();
    assert!(before >= 6, "seeded {before} snapshots");

    vault.set_history_max_items(2).expect("set max items");

    let removed = vault.trim_entry_history(uuid.clone()).expect("trim");
    assert!(removed > 0, "expected to trim something, got 0");

    let after = vault.entry_history(uuid).expect("history").len();
    assert_eq!(after, 2, "history capped at new max_items");
    assert_eq!(
        after + removed as usize,
        before,
        "removed count matches delta"
    );
}

#[test]
fn vault_trim_entry_history_returns_zero_when_within_limits() {
    let vault = open_basic();
    let uuid = seed_history(&vault, 2);
    // Default max_items on the fixture is generous; 2 snapshots is
    // comfortably under it. Sanity-check, then trim — expect zero.
    let max = vault.history_max_items().expect("max items");
    assert!(
        !(0..=2).contains(&max),
        "fixture max_items={max}, test assumes headroom"
    );

    let removed = vault.trim_entry_history(uuid.clone()).expect("trim");
    assert_eq!(removed, 0);

    let after = vault.entry_history(uuid).expect("history").len();
    assert_eq!(after, 2, "history untouched when within limits");
}
