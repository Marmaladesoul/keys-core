//! Integration tests for the slice 8I-B FFI surface — the
//! `VaultFieldProtector` trait parameter on [`Vault::new`] and
//! [`Vault::create_empty`].
//!
//! Mirrors the upstream `keepass-core` `field_protector` tests, but
//! drives the protector through the FFI's `Arc<dyn VaultFieldProtector>`
//! shape rather than the upstream `Arc<dyn FieldProtector>` shape.
//!
//! Coverage:
//! - `vault_new_accepts_protector_and_wraps_protected_fields` — open
//!   a fresh vault with a protector and confirm reveal still returns
//!   the original plaintext.
//! - `vault_create_empty_accepts_protector` — `create_empty` accepts
//!   a protector; entries added afterwards round-trip via reveal.
//! - `vault_new_without_protector_matches_legacy_behaviour` — the
//!   `None` path is unchanged.
//! - `vault_protector_error_propagates` — a wrap failure surfaces as
//!   [`VaultError::Protector`] from `Vault::new`.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use keys_ffi::{EntryCreate, Vault, VaultError, VaultFieldProtector, VaultProtectorError};
use tempfile::{NamedTempFile, TempDir};

const PASSWORD_FIELD: &str = "Password";

/// Test-only protector: returns a fixed 32-byte session key. The
/// in-memory wrap layer (AES-GCM) lives inside keepass-core; the
/// test just needs to hand it a key.
#[derive(Debug)]
struct XorProtector {
    /// The byte the legacy XOR test used as its wrap key. Reused
    /// here as a seed for the 32-byte key so the test names stay
    /// recognisable and each test instance still produces a
    /// distinct session key.
    key: u8,
}

impl VaultFieldProtector for XorProtector {
    fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
        Ok(vec![self.key; 32])
    }
}

/// Protector whose `acquire_session_key` always fails. Drives the
/// `VaultError::Protector` propagation test.
#[derive(Debug)]
struct FailingWrapProtector;

impl VaultFieldProtector for FailingWrapProtector {
    fn acquire_session_key(&self) -> Result<Vec<u8>, VaultProtectorError> {
        Err(VaultProtectorError::KeyUnavailable(
            "synthetic key-unavailable failure".into(),
        ))
    }
}

/// Save `vault`'s in-memory state to a temp file and reopen via
/// `Vault::new` with the supplied protector.
fn save_and_reopen(
    vault: &Vault,
    password: &str,
    protector: Option<Arc<dyn VaultFieldProtector>>,
) -> (Arc<Vault>, NamedTempFile) {
    let bytes = vault.save_to_bytes().expect("save");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    tmp.write_all(&bytes).expect("write");
    tmp.flush().expect("flush");
    let path = tmp.path().to_string_lossy().into_owned();
    let reopened = Vault::new(path, password.to_owned(), protector).expect("reopen");
    (reopened, tmp)
}

/// Build a fresh on-disk vault with one entry that has a password
/// plus one protected custom field. Returns (path, tempdir holding
/// it, password, the entry's uuid).
fn fresh_vault_with_protected_entry(
    password: &str,
    pw_value: &str,
    protected_key: &str,
    protected_value: &str,
) -> (String, TempDir, String) {
    let dir = TempDir::new().expect("tempdir");
    let mut path: PathBuf = dir.path().to_path_buf();
    path.push("fixture.kdbx");
    let path_str = path.to_string_lossy().into_owned();

    // Build without a protector so plaintext lands in the file
    // straightforwardly. Then we'll reopen with a protector.
    let vault = Vault::create_empty(
        path_str.clone(),
        password.to_owned(),
        "Protector Fixture".to_owned(),
        None,
        None,
    )
    .expect("create_empty");

    let root_groups = vault.list_groups().expect("list_groups");
    let root_uuid = root_groups
        .first()
        .map(|g| g.uuid.clone())
        .expect("root group");

    let entry_uuid = vault
        .create_entry(EntryCreate::new("Login", root_uuid))
        .expect("create_entry");

    // Set the structural password and one protected custom field.
    vault
        .set_protected_field(
            entry_uuid.clone(),
            PASSWORD_FIELD.to_owned(),
            pw_value.to_owned(),
        )
        .expect("set password");
    vault
        .set_protected_field(
            entry_uuid.clone(),
            protected_key.to_owned(),
            protected_value.to_owned(),
        )
        .expect("set protected custom field");

    // Persist so the protector-equipped reopen has wrapped bytes to
    // populate the side table from.
    let bytes = vault.save_to_bytes().expect("save");
    std::fs::write(&path_str, &bytes).expect("write file");

    (path_str, dir, entry_uuid)
}

#[test]
fn vault_new_accepts_protector_and_wraps_protected_fields() {
    let (path, _dir, entry_uuid) =
        fresh_vault_with_protected_entry("pw", "s3cr3t-password", "API_KEY", "abc-123-def");

    let protector: Arc<dyn VaultFieldProtector> = Arc::new(XorProtector { key: 0xa5 });
    let vault = Vault::new(path, "pw".to_owned(), Some(protector)).expect("reopen with protector");

    // The protected plaintext is NOT addressable via the plain read DTO:
    // `get_entry` returns the password slot as an unrevealed
    // `ProtectedField` (independent of protector), and the protected
    // custom field's `value` is empty by design.
    let entry = vault.get_entry(entry_uuid.clone()).expect("get_entry");
    assert!(
        !entry.password_field.revealed,
        "password slot is never revealed via the read DTO"
    );
    let api_field = entry
        .custom_fields
        .iter()
        .find(|c| c.name == "API_KEY")
        .expect("API_KEY field exists");
    assert!(
        api_field.is_protected,
        "field stays marked protected after wrap"
    );
    assert_eq!(
        api_field.value, "",
        "protected custom-field plaintext must not live in the read DTO"
    );

    // reveal_field unwraps via the protector and returns the original
    // plaintext.
    let revealed_pw = vault
        .reveal_field(entry_uuid.clone(), PASSWORD_FIELD.to_owned())
        .expect("reveal password");
    assert_eq!(revealed_pw, "s3cr3t-password");

    let revealed_api = vault
        .reveal_field(entry_uuid, "API_KEY".to_owned())
        .expect("reveal API_KEY");
    assert_eq!(revealed_api, "abc-123-def");
}

#[test]
fn vault_create_empty_accepts_protector() {
    let dir = TempDir::new().expect("tempdir");
    let mut path: PathBuf = dir.path().to_path_buf();
    path.push("fresh.kdbx");
    let path_str = path.to_string_lossy().into_owned();

    let protector: Arc<dyn VaultFieldProtector> = Arc::new(XorProtector { key: 0x33 });

    let vault = Vault::create_empty(
        path_str,
        "pw".to_owned(),
        "Fresh".to_owned(),
        Some(Arc::clone(&protector)),
        None,
    )
    .expect("create_empty with protector");

    let root_groups = vault.list_groups().expect("list_groups");
    let root_uuid = root_groups
        .first()
        .map(|g| g.uuid.clone())
        .expect("root group");
    let entry_uuid = vault
        .create_entry(EntryCreate::new("E", root_uuid))
        .expect("create_entry");

    vault
        .set_protected_field(
            entry_uuid.clone(),
            PASSWORD_FIELD.to_owned(),
            "fresh-pw".to_owned(),
        )
        .expect("set password");
    vault
        .set_protected_field(entry_uuid.clone(), "TOKEN".to_owned(), "tok-xyz".to_owned())
        .expect("set TOKEN");

    // Reveal-through-protector round-trip.
    let pw = vault
        .reveal_field(entry_uuid.clone(), PASSWORD_FIELD.to_owned())
        .expect("reveal password");
    assert_eq!(pw, "fresh-pw");
    let tok = vault
        .reveal_field(entry_uuid.clone(), "TOKEN".to_owned())
        .expect("reveal TOKEN");
    assert_eq!(tok, "tok-xyz");

    // Save + reopen with the same protector also round-trips.
    let (reopened, _tmp) = save_and_reopen(&vault, "pw", Some(protector));
    let pw2 = reopened
        .reveal_field(entry_uuid.clone(), PASSWORD_FIELD.to_owned())
        .expect("reveal pw after reopen");
    assert_eq!(pw2, "fresh-pw");
    let tok2 = reopened
        .reveal_field(entry_uuid, "TOKEN".to_owned())
        .expect("reveal TOKEN after reopen");
    assert_eq!(tok2, "tok-xyz");
}

#[test]
fn vault_new_without_protector_matches_legacy_behaviour() {
    let (path, _dir, entry_uuid) =
        fresh_vault_with_protected_entry("pw", "legacy-pw", "LEGACY_FIELD", "legacy-val");

    // No protector — pre-slice-8I-B behaviour: plaintext lives in the
    // model. The read DTO carries it directly.
    let vault = Vault::new(path, "pw".to_owned(), None).expect("reopen without protector");

    let entry = vault.get_entry(entry_uuid.clone()).expect("get_entry");
    // Read DTO contract: protected custom fields surface with
    // `value == ""` regardless of whether a protector is in use; the
    // distinction is only observable internally (the plaintext lives
    // in the model on the `None` path, in the side table on the
    // `Some(...)` path).
    let legacy = entry
        .custom_fields
        .iter()
        .find(|c| c.name == "LEGACY_FIELD")
        .expect("LEGACY_FIELD field exists");
    assert!(legacy.is_protected);
    assert_eq!(legacy.value, "");
    assert!(!entry.password_field.revealed);

    // reveal_field works via the same legacy path.
    let pw = vault
        .reveal_field(entry_uuid.clone(), PASSWORD_FIELD.to_owned())
        .expect("reveal");
    assert_eq!(pw, "legacy-pw");
    let val = vault
        .reveal_field(entry_uuid, "LEGACY_FIELD".to_owned())
        .expect("reveal LEGACY_FIELD");
    assert_eq!(val, "legacy-val");
}

#[test]
fn vault_protector_error_propagates() {
    let (path, _dir, _entry_uuid) =
        fresh_vault_with_protected_entry("pw", "any-pw", "ANY", "any-val");

    let failing: Arc<dyn VaultFieldProtector> = Arc::new(FailingWrapProtector);
    let err = Vault::new(path, "pw".to_owned(), Some(failing))
        .expect_err("wrap failure must surface as a VaultError");

    match err {
        VaultError::Protector(msg) => {
            assert!(
                msg.contains("synthetic key-unavailable failure"),
                "protector error must carry the implementation-supplied detail; got: {msg}"
            );
        }
        other => panic!("expected VaultError::Protector, got {other:?}"),
    }
}
