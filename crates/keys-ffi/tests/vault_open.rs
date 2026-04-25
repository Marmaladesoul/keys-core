//! Integration tests for slice 2 — `Vault::open` + `lock`.
//!
//! Drives the public FFI surface against the `keepass-core` fixture corpus
//! at `KeepassCore/tests/fixtures/`. Path resolution relies on the path-dep
//! relationship between the two repos (CI's side-by-side checkout puts
//! `KeepassCore` next to `KeysCore`).

use std::path::PathBuf;

use keys_ffi::{Vault, VaultError};

/// Resolve a fixture path from the `KeepassCore` repo's workspace-level
/// fixture corpus. The two repos are sibling directories on disk
/// (`Keys/KeysCore` and `Keys/KeepassCore`), with the relationship
/// already enforced by `crates/keys-ffi/Cargo.toml`'s path deps.
fn fixture(rel: &str) -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../../../KeepassCore/tests/fixtures")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn opens_kdbx3_basic_fixture() {
    let vault = Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "test-basic-002".to_owned(),
    )
    .expect("kdbx3 fixture should open");
    assert!(!vault.is_locked());
}

#[test]
fn opens_kdbx4_recycle_fixture() {
    let vault = Vault::new(
        fixture("pykeepass/recycle.kdbx"),
        "test-recycle-102".to_owned(),
    )
    .expect("kdbx4 fixture should open");
    assert!(!vault.is_locked());
}

#[test]
fn wrong_password_returns_wrong_key() {
    let err = Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "definitely-not-the-password".to_owned(),
    )
    .expect_err("wrong password should fail");
    assert!(matches!(err, VaultError::WrongKey), "got {err:?}");
}

#[test]
fn bad_magic_returns_format() {
    let err = Vault::new(fixture("malformed/bad-magic.kdbx"), "irrelevant".to_owned())
        .expect_err("bad magic should fail");
    assert!(matches!(err, VaultError::Format), "got {err:?}");
}

#[test]
fn corrupt_header_returns_wrong_key() {
    // `hmac-fail.kdbx` has a valid signature but corrupt HMAC blocks —
    // the load-bearing error-collapse case from the spec. If this ever
    // returns `Format`, the collapse rule has been broken.
    let err = Vault::new(fixture("malformed/hmac-fail.kdbx"), "irrelevant".to_owned())
        .expect_err("hmac-fail should fail");
    assert!(matches!(err, VaultError::WrongKey), "got {err:?}");
}

#[test]
fn missing_path_returns_io() {
    let err = Vault::new(
        "/this/path/does/not/exist.kdbx".to_owned(),
        "irrelevant".to_owned(),
    )
    .expect_err("missing path should fail");
    assert!(matches!(err, VaultError::Io(_)), "got {err:?}");
}

#[test]
fn lock_clears_state_and_is_idempotent() {
    let vault = Vault::new(
        fixture("keepassxc/kdbx3-basic.kdbx"),
        "test-basic-002".to_owned(),
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
    let vault = Vault::new(path.clone(), "test-basic-002".to_owned()).expect("fixture should open");
    assert_eq!(vault.path(), path);

    vault.lock().expect("lock");
    assert_eq!(vault.path(), path, "path() must survive lock()");
}
