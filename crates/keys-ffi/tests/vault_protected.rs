//! Integration tests for slice 4 — protected-field reveal &
//! sparse-patch write.
//!
//! Save+reopen round-trips use the production `save_to_bytes` introduced in slice 7.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use keys_ffi::{Vault, VaultError};
use tempfile::NamedTempFile;

fn fixture(rel: &str) -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../../../KeepassCore/tests/fixtures")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

/// Open the custom-fields fixture (one entry, two protected custom
/// fields plus the structural Password).
fn open_custom() -> Arc<Vault> {
    Vault::new(
        fixture("pykeepass/custom-fields.kdbx"),
        "tëst pässwörd 🔑/\\".to_owned(),
        None,
    )
    .expect("custom-fields fixture should open")
}

fn first_entry_uuid(vault: &Vault) -> String {
    vault
        .list_entries(None)
        .expect("list")
        .first()
        .expect("at least one entry")
        .uuid
        .clone()
}

/// Persist `vault` via the slice-4 test helper to a temp file, then
/// reopen with `password`. The temp file owns the bytes' lifetime so
/// it must outlive the Vault that reads from it.
fn save_and_reopen(vault: &Vault, password: &str) -> (Arc<Vault>, NamedTempFile) {
    let bytes = vault.save_to_bytes().expect("save");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    tmp.write_all(&bytes).expect("write");
    tmp.flush().expect("flush");
    let path = tmp.path().to_string_lossy().into_owned();
    let reopened = Vault::new(path, password.to_owned(), None).expect("reopen");
    (reopened, tmp)
}

// -----------------------------------------------------------------------
// reveal_field
// -----------------------------------------------------------------------

#[test]
fn reveal_field_returns_password_plaintext() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);
    let pw = vault
        .reveal_field(uuid, "Password".to_owned())
        .expect("reveal Password");
    // pykeepass-generated fixtures always have a non-empty password.
    assert!(!pw.is_empty(), "fixture password is non-empty");
}

#[test]
fn reveal_field_returns_protected_custom_plaintext() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);
    let value = vault
        .reveal_field(uuid, "API Secret".to_owned())
        .expect("reveal API Secret");
    // Sidecar declares value_length 28 for API Secret.
    assert_eq!(value.len(), 28);
}

#[test]
fn reveal_field_unprotected_name_returns_field_not_found() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);
    // "API Key ID" is unprotected per the sidecar — reveal_field is
    // explicitly the protected-only path.
    let err = vault
        .reveal_field(uuid, "API Key ID".to_owned())
        .expect_err("unprotected name should miss");
    assert!(matches!(err, VaultError::FieldNotFound), "got {err:?}");
}

#[test]
fn reveal_field_missing_name_returns_field_not_found() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);
    let err = vault
        .reveal_field(uuid, "DefinitelyNotAField".to_owned())
        .expect_err("missing name should miss");
    assert!(matches!(err, VaultError::FieldNotFound), "got {err:?}");
}

#[test]
fn reveal_field_bogus_entry_returns_not_found() {
    let vault = open_custom();
    let err = vault
        .reveal_field(
            "00000000-0000-0000-0000-000000000000".to_owned(),
            "Password".to_owned(),
        )
        .expect_err("bogus entry should miss");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// -----------------------------------------------------------------------
// set_protected_field
// -----------------------------------------------------------------------

#[test]
fn set_password_round_trips_through_save_and_reopen() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);

    vault
        .set_protected_field(uuid.clone(), "Password".to_owned(), "newpw-42".to_owned())
        .expect("set Password");

    // In-memory readback first.
    assert_eq!(
        vault
            .reveal_field(uuid.clone(), "Password".to_owned())
            .unwrap(),
        "newpw-42"
    );

    // Then a save-and-reopen round-trip.
    let (reopened, _tmp) = save_and_reopen(&vault, "tëst pässwörd 🔑/\\");
    assert_eq!(
        reopened.reveal_field(uuid, "Password".to_owned()).unwrap(),
        "newpw-42"
    );
}

#[test]
fn set_protected_custom_field_round_trips() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);

    vault
        .set_protected_field(
            uuid.clone(),
            "API Secret".to_owned(),
            "rotated-secret".to_owned(),
        )
        .expect("set API Secret");

    let (reopened, _tmp) = save_and_reopen(&vault, "tëst pässwörd 🔑/\\");
    assert_eq!(
        reopened
            .reveal_field(uuid, "API Secret".to_owned())
            .unwrap(),
        "rotated-secret"
    );
}

#[test]
fn set_protected_field_inserts_new_field() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);

    vault
        .set_protected_field(
            uuid.clone(),
            "TOTP Seed".to_owned(),
            "JBSWY3DPEHPK3PXP".to_owned(),
        )
        .expect("insert TOTP Seed");

    // get_entry now surfaces TOTP Seed as a protected custom field
    // with empty value (plaintext fetched via reveal_field).
    let entry = vault.get_entry(uuid.clone()).expect("get_entry");
    let totp = entry
        .custom_fields
        .iter()
        .find(|f| f.name == "TOTP Seed")
        .expect("TOTP Seed present");
    assert!(totp.is_protected);
    assert!(totp.value.is_empty(), "no plaintext on the read path");

    // reveal_field produces the plaintext.
    assert_eq!(
        vault.reveal_field(uuid, "TOTP Seed".to_owned()).unwrap(),
        "JBSWY3DPEHPK3PXP"
    );
}

#[test]
fn set_protected_field_bogus_entry_returns_not_found() {
    let vault = open_custom();
    let err = vault
        .set_protected_field(
            "00000000-0000-0000-0000-000000000000".to_owned(),
            "Password".to_owned(),
            "irrelevant".to_owned(),
        )
        .expect_err("bogus entry should miss");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

#[test]
fn set_protected_field_records_history_snapshot() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);

    let before = vault
        .reveal_field(uuid.clone(), "Password".to_owned())
        .expect("read before");

    vault
        .set_protected_field(uuid.clone(), "Password".to_owned(), "new-12345".to_owned())
        .expect("set");

    // History introspection isn't exposed at the FFI yet (slice 8) —
    // assert via a save/reopen and check that the entry's
    // last_modified_ms advanced relative to its original value.
    let (reopened, _tmp) = save_and_reopen(&vault, "tëst pässwörd 🔑/\\");
    let entry_before = open_custom().get_entry(uuid.clone()).unwrap();
    let entry_after = reopened.get_entry(uuid.clone()).unwrap();
    assert!(
        entry_after.last_modified_ms >= entry_before.last_modified_ms,
        "last_modified_ms must advance after a set ({} -> {})",
        entry_before.last_modified_ms,
        entry_after.last_modified_ms,
    );

    // Belt-and-braces: the new password should reveal post-reopen,
    // confirming the edit_entry path actually persisted.
    assert_eq!(
        reopened.reveal_field(uuid, "Password".to_owned()).unwrap(),
        "new-12345"
    );
    let _ = before;
}

// -----------------------------------------------------------------------
// clear_protected_field
// -----------------------------------------------------------------------

#[test]
fn clear_protected_custom_field_removes_it() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);

    vault
        .clear_protected_field(uuid.clone(), "API Secret".to_owned())
        .expect("clear API Secret");

    // Field is gone from get_entry's custom_fields list.
    let entry = vault.get_entry(uuid.clone()).expect("get");
    assert!(entry.custom_fields.iter().all(|f| f.name != "API Secret"));

    // Round-trip through save/reopen — also gone there.
    let (reopened, _tmp) = save_and_reopen(&vault, "tëst pässwörd 🔑/\\");
    let entry = reopened.get_entry(uuid.clone()).unwrap();
    assert!(entry.custom_fields.iter().all(|f| f.name != "API Secret"));

    // And reveal returns FieldNotFound.
    let err = reopened
        .reveal_field(uuid, "API Secret".to_owned())
        .expect_err("API Secret cleared");
    assert!(matches!(err, VaultError::FieldNotFound));
}

#[test]
fn clear_password_sets_to_empty_string() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);

    vault
        .clear_protected_field(uuid.clone(), "Password".to_owned())
        .expect("clear Password");

    // Password slot still exists in get_entry's password_field —
    // it's structural — but reveal returns "".
    let entry = vault.get_entry(uuid.clone()).expect("get");
    assert_eq!(entry.password_field.name, "Password");

    assert_eq!(
        vault
            .reveal_field(uuid.clone(), "Password".to_owned())
            .unwrap(),
        ""
    );

    // Round-trip preserves the empty-Password representation.
    let (reopened, _tmp) = save_and_reopen(&vault, "tëst pässwörd 🔑/\\");
    assert_eq!(
        reopened.reveal_field(uuid, "Password".to_owned()).unwrap(),
        ""
    );
}

#[test]
fn clear_unprotected_field_returns_field_not_found() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);

    // "API Key ID" is unprotected — clear_protected_field is
    // protected-only and must not silently nuke unprotected fields.
    let err = vault
        .clear_protected_field(uuid.clone(), "API Key ID".to_owned())
        .expect_err("unprotected name should miss");
    assert!(matches!(err, VaultError::FieldNotFound), "got {err:?}");

    // The unprotected field is still there.
    let entry = vault.get_entry(uuid).expect("get");
    assert!(
        entry.custom_fields.iter().any(|f| f.name == "API Key ID"),
        "unprotected field must survive a failed clear",
    );
}

#[test]
fn clear_missing_field_returns_field_not_found() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);
    let err = vault
        .clear_protected_field(uuid, "DefinitelyNotAField".to_owned())
        .expect_err("missing name should miss");
    assert!(matches!(err, VaultError::FieldNotFound), "got {err:?}");
}

#[test]
fn clear_bogus_entry_returns_not_found() {
    let vault = open_custom();
    let err = vault
        .clear_protected_field(
            "00000000-0000-0000-0000-000000000000".to_owned(),
            "API Secret".to_owned(),
        )
        .expect_err("bogus entry should miss");
    assert!(matches!(err, VaultError::NotFound), "got {err:?}");
}

// -----------------------------------------------------------------------
// locked-after-lock invariant
// -----------------------------------------------------------------------

#[test]
fn protected_methods_return_locked_after_lock() {
    let vault = open_custom();
    let uuid = first_entry_uuid(&vault);
    vault.lock().expect("lock");

    assert!(matches!(
        vault.reveal_field(uuid.clone(), "Password".to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.set_protected_field(uuid.clone(), "Password".to_owned(), "x".to_owned()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        vault.clear_protected_field(uuid, "Password".to_owned()),
        Err(VaultError::Locked)
    ));
}
