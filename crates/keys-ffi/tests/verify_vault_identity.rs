//! Integration tests for [`verify_vault_identity`] — the vault-identity
//! verdict a consumer uses to reject re-anchoring a vault to the wrong KDBX
//! file.
//!
//! The verdict is three-way: `Match` (same vault — proceed), `Mismatch`
//! (decrypts to a different identity — definitive reject), and `Undecryptable`
//! (won't open under this credential — ambiguous: wrong file, corrupt, or the
//! genuine vault re-keyed since the credential was cached, so the consumer
//! re-derives rather than hard-rejecting). Missing / not-a-KDBX surface as
//! errors, not verdicts.

use std::path::{Path, PathBuf};
use tempfile::TempDir;

use keys_ffi::{
    VaultError, VaultIdentityVerdict, create_vault, generate_keyfile, verify_vault_identity,
};

fn fresh_path(dir: &TempDir, name: &str) -> String {
    let mut path: PathBuf = dir.path().to_path_buf();
    path.push(name);
    path.to_string_lossy().into_owned()
}

/// Mint a fresh password-only vault at `path` via the production creation
/// entry point.
async fn create(path: &str, database_name: &str) {
    create_vault(
        path.to_owned(),
        "pw".to_owned(),
        None,
        database_name.to_owned(),
        None,
        None,
    )
    .await
    .expect("create");
}

/// The expected identity a caller would hold: the root group's UUID.
///
/// This opens the KDBX through `keepass-core` — the same layer
/// `verify_vault_identity` reads its root through — so it is NOT a fully
/// independent oracle (the old `Vault::list_groups` walk that provided
/// that independence went with the façade). The load-bearing assertion is
/// therefore `different_vault_mismatches`: two genuinely distinct vaults
/// yield distinct roots, so a `Mismatch` verdict exercises the real
/// compare-and-classify path end-to-end. `same_vault_matches` degrades to
/// confirming the verdict plumbing rather than root extraction itself.
fn root_uuid(path: &str, password: &str) -> String {
    use keepass_core::CompositeKey;
    use keepass_core::kdbx::Kdbx;
    let composite = CompositeKey::from_password(password.as_bytes());
    let kdbx = Kdbx::open(Path::new(path))
        .expect("open")
        .read_header()
        .expect("header")
        .unlock(&composite)
        .expect("unlock");
    kdbx.vault().root.id.0.to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn same_vault_matches() {
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "vault.kdbx");
    create(&path, "Vault").await;
    let expected = root_uuid(&path, "pw");

    let verdict = verify_vault_identity(path, "pw".to_owned(), None, expected).expect("verify");
    assert_eq!(verdict, VaultIdentityVerdict::Match);
}

#[tokio::test(flavor = "multi_thread")]
async fn different_vault_mismatches() {
    let dir = TempDir::new().expect("tempdir");
    let a = fresh_path(&dir, "a.kdbx");
    let b = fresh_path(&dir, "b.kdbx");
    create(&a, "A").await;
    create(&b, "B").await;
    let a_root = root_uuid(&a, "pw");

    // B decrypts under the same password but is a different vault — the
    // dangerous case the guard exists for. Definitive Mismatch.
    let verdict = verify_vault_identity(b, "pw".to_owned(), None, a_root).expect("verify");
    assert_eq!(verdict, VaultIdentityVerdict::Mismatch);
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_is_path_agnostic() {
    // The whole point of recovery: the vault moved, so the path changed but the
    // identity did not. The same bytes at a new path still Match.
    let dir = TempDir::new().expect("tempdir");
    let original = fresh_path(&dir, "original.kdbx");
    let moved = fresh_path(&dir, "moved-elsewhere.kdbx");
    create(&original, "Vault").await;
    std::fs::copy(&original, &moved).expect("copy to new path");
    let expected = root_uuid(&original, "pw");

    let verdict = verify_vault_identity(moved, "pw".to_owned(), None, expected).expect("verify");
    assert_eq!(verdict, VaultIdentityVerdict::Match);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_is_undecryptable_not_mismatch() {
    // The load-bearing distinction (re-key contract): a credential that doesn't
    // fit yields Undecryptable, NOT Mismatch — so a consumer re-derives rather
    // than declaring the file a different vault. (A genuine vault re-keyed on
    // another device reaches exactly this arm under a stale cached credential.)
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "vault.kdbx");
    create_vault(
        path.clone(),
        "correct".to_owned(),
        None,
        "Vault".to_owned(),
        None,
        None,
    )
    .await
    .expect("create");
    let expected = root_uuid(&path, "correct");

    let verdict = verify_vault_identity(path, "wrong".to_owned(), None, expected).expect("verify");
    assert_eq!(verdict, VaultIdentityVerdict::Undecryptable);
}

#[test]
fn missing_file_errors_io() {
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "does-not-exist.kdbx");
    let result = verify_vault_identity(
        path,
        "pw".to_owned(),
        None,
        "11111111-1111-1111-1111-111111111111".to_owned(),
    );
    assert!(matches!(result, Err(VaultError::Io(_))), "{result:?}");
}

#[test]
fn non_kdbx_file_errors_format() {
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "notes.txt");
    std::fs::write(&path, b"this is not a kdbx file").expect("write");
    let result = verify_vault_identity(
        path,
        "pw".to_owned(),
        None,
        "11111111-1111-1111-1111-111111111111".to_owned(),
    );
    assert!(matches!(result, Err(VaultError::Format)), "{result:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn keyfile_vault_without_its_keyfile_is_undecryptable() {
    // A keyfile-keyed vault won't open password-only, nor under a wrong
    // keyfile, so it reports Undecryptable regardless of the expected UUID
    // (the credential is judged before any identity comparison). The keyfile
    // *Match* case — right password + right keyfile — is pinned end-to-end in
    // the keyhole scenario, which can read the keyed vault's root via a
    // keyfile-bearing engine open (there is no password-only reader here).
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "keyed.kdbx");
    let keyfile = generate_keyfile().expect("mint keyfile");
    create_vault(
        path.clone(),
        "pw".to_owned(),
        Some(keyfile),
        "Keyed".to_owned(),
        None,
        None,
    )
    .await
    .expect("create keyed");
    let any = "11111111-1111-1111-1111-111111111111".to_owned();

    // Right password, NO keyfile → Undecryptable.
    let without =
        verify_vault_identity(path.clone(), "pw".to_owned(), None, any.clone()).expect("verify");
    assert_eq!(without, VaultIdentityVerdict::Undecryptable);

    // Right password, WRONG keyfile → Undecryptable.
    let wrong_keyfile = generate_keyfile().expect("mint second keyfile");
    let wrong =
        verify_vault_identity(path, "pw".to_owned(), Some(wrong_keyfile), any).expect("verify");
    assert_eq!(wrong, VaultIdentityVerdict::Undecryptable);
}
