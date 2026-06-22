//! Integration tests for slice 7 — `save`, `save_to_bytes`,
//! `rekey`. Atomic-write loop is at the FFI facade pending an
//! upstream `Kdbx::save_to_path`.

use std::fs;
use std::sync::Arc;

use keys_ffi::{Vault, VaultError};
use tempfile::TempDir;

mod common;
use common::fixture;

/// Copy a fixture into a writable temp directory and open the copy
/// — `save()` writes back to its constructor path, so we must not
/// clobber the on-disk fixture corpus.
fn open_basic_in_temp() -> (Arc<Vault>, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let dest = dir.path().join("basic.kdbx");
    fs::copy(fixture("keepassxc/kdbx3-basic.kdbx"), &dest).expect("copy fixture");
    let vault = Vault::new(
        dest.to_string_lossy().into_owned(),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("open");
    (vault, dir)
}

// -----------------------------------------------------------------------
// save_to_bytes
// -----------------------------------------------------------------------

#[test]
fn save_to_bytes_round_trips_through_in_memory_reopen() {
    let (vault, _dir) = open_basic_in_temp();
    let bytes = vault.save_to_bytes().expect("save");

    // Reopen via a fresh tempfile to exercise the bytes round-trip
    // without going through `save()`.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("roundtrip.kdbx");
    fs::write(&path, &bytes).unwrap();
    let reopened = Vault::new(
        path.to_string_lossy().into_owned(),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("reopen save_to_bytes output");
    assert_eq!(
        reopened.list_entries(None).unwrap().len(),
        vault.list_entries(None).unwrap().len(),
    );
}

// -----------------------------------------------------------------------
// save
// -----------------------------------------------------------------------

#[test]
fn save_writes_to_constructor_path_and_reopens() {
    let (vault, _dir) = open_basic_in_temp();
    let path = vault.path();
    let count_before = vault.list_entries(None).unwrap().len();

    vault.save().expect("save");

    let reopened = Vault::new(path, "tëst pässwörd 🔑/\\".to_owned(), None).expect("reopen");
    assert_eq!(reopened.list_entries(None).unwrap().len(), count_before);
}

#[test]
fn save_preserves_recent_mutations() {
    let (vault, _dir) = open_basic_in_temp();
    let path = vault.path();

    let group = vault
        .list_groups()
        .unwrap()
        .into_iter()
        .find(|g| g.name == "Personal")
        .unwrap()
        .uuid;
    let new_uuid = vault
        .create_entry(keys_ffi::EntryCreate::new("Saved", group))
        .expect("create");
    vault.save().expect("save");

    let reopened = Vault::new(path, "tëst pässwörd 🔑/\\".to_owned(), None).expect("reopen");
    assert!(
        reopened
            .list_entries(None)
            .unwrap()
            .iter()
            .any(|e| e.uuid == new_uuid),
        "newly-created entry survives save+reopen",
    );
}

// -----------------------------------------------------------------------
// rekey
// -----------------------------------------------------------------------

#[test]
fn rekey_then_save_then_reopen_with_new_password() {
    let (vault, _dir) = open_basic_in_temp();
    let path = vault.path();

    vault.rekey("new-master-pw".to_owned()).expect("rekey");
    vault.save().expect("save after rekey");

    let reopened =
        Vault::new(path, "new-master-pw".to_owned(), None).expect("reopen with new password");
    assert!(!reopened.is_locked());
}

#[test]
fn rekey_then_save_old_password_returns_wrong_key() {
    let (vault, _dir) = open_basic_in_temp();
    let path = vault.path();

    vault.rekey("rotated".to_owned()).expect("rekey");
    vault.save().expect("save after rekey");

    let err = Vault::new(path, "tëst pässwörd 🔑/\\".to_owned(), None)
        .expect_err("old password should fail after rekey+save");
    assert!(matches!(err, VaultError::WrongKey), "got {err:?}");
}

#[test]
fn rekey_without_save_leaves_disk_unchanged() {
    let (vault, _dir) = open_basic_in_temp();
    let path = vault.path();

    vault.rekey("new".to_owned()).expect("rekey in memory");
    // No save() — disk still has the original key.
    let reopened = Vault::new(path, "tëst pässwörd 🔑/\\".to_owned(), None)
        .expect("on-disk vault still uses original password");
    assert!(!reopened.is_locked());
}

// -----------------------------------------------------------------------
// locked-after-lock
// -----------------------------------------------------------------------

#[test]
fn save_methods_return_locked_after_lock() {
    let (vault, _dir) = open_basic_in_temp();
    vault.lock().expect("lock");
    assert!(matches!(vault.save(), Err(VaultError::Locked)));
    assert!(matches!(vault.save_to_bytes(), Err(VaultError::Locked)));
    assert!(matches!(
        vault.rekey("x".to_owned()),
        Err(VaultError::Locked)
    ));
}
