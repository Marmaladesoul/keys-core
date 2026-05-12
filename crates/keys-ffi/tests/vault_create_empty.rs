//! Integration tests for [`Vault::create_empty`] — the FFI fresh-
//! vault constructor (slice 8E PR 2; consumes upstream PR 1's
//! `Kdbx::<Unlocked>::create_empty_v4`).
//!
//! Smoke surface: write to disk, reopen via [`Vault::new`], confirm
//! the round-trip preserves the database name + accepts mutations.
//! Negative path: wrong-password reopen rejects.

use std::path::PathBuf;
use tempfile::TempDir;

use keys_ffi::{Vault, VaultError};

fn fresh_path(dir: &TempDir, name: &str) -> String {
    let mut path: PathBuf = dir.path().to_path_buf();
    path.push(name);
    path.to_string_lossy().into_owned()
}

#[test]
fn create_empty_writes_file_and_reopens_with_same_password() {
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "test.kdbx");

    let _vault = Vault::create_empty(
        path.clone(),
        "hunter2".to_owned(),
        "My Test Vault".to_owned(),
        None,
    )
    .expect("create_empty");

    // File exists at the path.
    assert!(
        std::path::Path::new(&path).exists(),
        "create_empty must write the file"
    );

    // Reopen via the standard path.
    let reopened = Vault::new(path, "hunter2".to_owned(), None).expect("reopen");
    let summaries = reopened.list_entries(None).expect("list");
    assert!(summaries.is_empty(), "fresh vault has no entries");
    let groups = reopened.list_groups().expect("list groups");
    // Root group only.
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "My Test Vault");
}

#[test]
fn create_empty_wrong_password_after_reopen_rejects() {
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "test.kdbx");

    let _vault = Vault::create_empty(
        path.clone(),
        "correct-password".to_owned(),
        "Vault".to_owned(),
        None,
    )
    .expect("create_empty");

    let result = Vault::new(path, "wrong-password".to_owned(), None);
    assert!(matches!(result, Err(VaultError::WrongKey)));
}

#[test]
fn create_empty_accepts_mutations_then_persists_on_save() {
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "test.kdbx");

    let vault = Vault::create_empty(path.clone(), "pw".to_owned(), "Vault".to_owned(), None)
        .expect("create_empty");

    // Add an entry, save, reopen.
    let groups = vault.list_groups().expect("list groups");
    let root = &groups[0];
    let create = keys_ffi::EntryCreate::new("Sample", root.uuid.clone());
    let _uuid = vault.create_entry(create).expect("create_entry");
    vault.save().expect("save");

    // Reopen — entry should survive.
    let reopened = Vault::new(path, "pw".to_owned(), None).expect("reopen");
    let summaries = reopened.list_entries(None).expect("list");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].title, "Sample");
}

#[test]
fn create_empty_io_error_on_missing_parent_directory() {
    // Path whose parent doesn't exist — should surface as a typed Io error
    // rather than panic.
    let path = "/nonexistent-parent-dir-for-keys-test/foo.kdbx".to_owned();
    let result = Vault::create_empty(path, "pw".to_owned(), "Vault".to_owned(), None);
    assert!(matches!(result, Err(VaultError::Io(_))));
}
