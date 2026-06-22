//! Integration tests for slice 2 — `Vault::open` + `lock`.
//!
//! Drives the public FFI surface against the `keepass-core` fixture corpus.
//! Fixture paths resolve through the shared `common::fixture` helper — see
//! its module docs for the `KEYS_TEST_FIXTURES_DIR` contract.

use keys_ffi::{Vault, VaultError};

mod common;
use common::fixture;

#[test]
fn opens_kdbx3_basic_fixture() {
    let vault = Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("kdbx3 fixture should open");
    assert!(!vault.is_locked());
}

#[test]
fn opens_kdbx4_recycle_fixture() {
    let vault = Vault::new(
        fixture("pykeepass/recycle.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("kdbx4 fixture should open");
    assert!(!vault.is_locked());
}

#[test]
fn wrong_password_returns_wrong_key() {
    let err = Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "definitely-not-the-password".to_owned(),
        None,
    )
    .expect_err("wrong password should fail");
    assert!(matches!(err, VaultError::WrongKey), "got {err:?}");
}

#[test]
fn bad_magic_returns_format() {
    let err = Vault::new(
        fixture("malformed/bad-magic.kdbx"),
        "irrelevant".to_owned(),
        None,
    )
    .expect_err("bad magic should fail");
    assert!(matches!(err, VaultError::Format), "got {err:?}");
}

#[test]
fn corrupt_header_returns_wrong_key() {
    // `hmac-fail.kdbx` has a valid signature but corrupt HMAC blocks —
    // the load-bearing error-collapse case from the spec. If this ever
    // returns `Format`, the collapse rule has been broken.
    let err = Vault::new(
        fixture("malformed/hmac-fail.kdbx"),
        "irrelevant".to_owned(),
        None,
    )
    .expect_err("hmac-fail should fail");
    assert!(matches!(err, VaultError::WrongKey), "got {err:?}");
}

#[test]
fn missing_path_returns_io() {
    let err = Vault::new(
        "/this/path/does/not/exist.kdbx".to_owned(),
        "irrelevant".to_owned(),
        None,
    )
    .expect_err("missing path should fail");
    assert!(matches!(err, VaultError::Io(_)), "got {err:?}");
}

#[test]
fn lock_clears_state_and_is_idempotent() {
    let vault = Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("fixture should open");
    assert!(!vault.is_locked());

    vault.lock().expect("first lock");
    assert!(vault.is_locked());

    // Locking an already-locked vault is `Ok(())` — three SwiftUI
    // lifecycle paths (auto-timer, explicit, on-quit) shouldn't need
    // to coordinate.
    vault.lock().expect("second lock — idempotent");
    assert!(vault.is_locked());
}

#[test]
fn path_survives_lock() {
    let path = fixture("keepassxc/kdbx3-basic.kdbx");
    let vault = Vault::new(path.clone(), "tëst pässwörd 🔑/\\".to_owned(), None)
        .expect("fixture should open");
    assert_eq!(vault.path(), path);

    vault.lock().expect("lock");
    assert_eq!(vault.path(), path, "path() must survive lock()");
}
