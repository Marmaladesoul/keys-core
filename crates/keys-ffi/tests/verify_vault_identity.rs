//! Integration tests for [`verify_vault_identity`] — the vault-identity
//! verdict a consumer uses to reject re-anchoring a vault to the wrong KDBX
//! file.
//!
//! The verdict is four-way: `Match` (same vault — proceed), `Mismatch`
//! (decrypts to a different identity — definitive reject), `Undecryptable`
//! (the key was refused — ambiguous: wrong file, damage that can't be told
//! from a wrong key, or the genuine vault re-keyed since the credential was
//! cached, so the consumer re-derives rather than hard-rejecting), and
//! `Unreadable` (a KDBX4 file damaged past its keyed header HMAC, or header
//! damage found without the key — no credential will open it). Where KDBX3
//! and KDBX4 differ is covered below. Missing / not-a-KDBX
//! surface as errors, not verdicts.

mod common;

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

    let verdict =
        verify_vault_identity(path, "pw".to_owned(), None, expected, None).expect("verify");
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
    let verdict = verify_vault_identity(b, "pw".to_owned(), None, a_root, None).expect("verify");
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

    let verdict =
        verify_vault_identity(moved, "pw".to_owned(), None, expected, None).expect("verify");
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

    let verdict =
        verify_vault_identity(path, "wrong".to_owned(), None, expected, None).expect("verify");
    assert_eq!(verdict, VaultIdentityVerdict::Undecryptable);
}

/// Bytes in the empty block that ends a KDBX4 payload: a 32-byte HMAC tag plus
/// a 4-byte zero length.
const KDBX4_END_BLOCK_BYTES: usize = 32 + 4;

#[tokio::test(flavor = "multi_thread")]
async fn damaged_payload_is_unreadable_not_undecryptable() {
    // KDBX4: damage past the keyed header HMAC is not a key refusal: under the
    // right password it is Unreadable (re-prompting won't help), and only a
    // wrong password is Undecryptable — the HMAC is checked first, so it
    // still is.
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "vault.kdbx");
    create(&path, "Vault").await;
    let expected = root_uuid(&path, "pw");
    let intact = std::fs::read(&path).expect("read vault");
    // The last ciphertext byte of the first payload block: well past the
    // header, caught only by that block's HMAC.
    let last_data_byte = intact.len() - KDBX4_END_BLOCK_BYTES - 1;

    let mut corrupt = intact.clone();
    corrupt[last_data_byte] = !corrupt[last_data_byte];
    let truncated = &intact[..last_data_byte];

    for (name, bytes) in [
        ("corrupt.kdbx", corrupt.as_slice()),
        ("truncated.kdbx", truncated),
    ] {
        let damaged = fresh_path(&dir, name);
        std::fs::write(&damaged, bytes).expect("write damaged copy");
        let right = verify_vault_identity(
            damaged.clone(),
            "pw".to_owned(),
            None,
            expected.clone(),
            None,
        )
        .expect("verify");
        assert_eq!(
            right,
            VaultIdentityVerdict::Unreadable,
            "{name}, right password"
        );
        let wrong =
            verify_vault_identity(damaged, "wrong".to_owned(), None, expected.clone(), None)
                .expect("verify");
        assert_eq!(
            wrong,
            VaultIdentityVerdict::Undecryptable,
            "{name}, wrong password"
        );
    }
}

/// Bytes before a KDBX file's first header field: two 4-byte signatures and a
/// 4-byte format version.
const KDBX_PREAMBLE_BYTES: usize = 12;
/// A KDBX4 header field's type-and-length prefix: a 1-byte id, a 4-byte length.
const KDBX4_FIELD_PREFIX_BYTES: usize = 1 + 4;
/// The KDBX4 header field holding the KDF parameters (a `VarDictionary`).
const KDBX4_KDF_PARAMETERS_FIELD: u8 = 11;
/// Offset of the major-version byte inside a `VarDictionary` (`[minor, major]`).
const VAR_DICTIONARY_MAJOR_VERSION_AT: usize = 1;
/// The KDBX4 header field holding the master seed: any bytes parse, so a flip
/// there is caught only by the header's hash.
const KDBX4_MASTER_SEED_FIELD: u8 = 4;

/// Offset of the value of header field `id` in a KDBX4 file.
fn kdbx4_field_value_at(bytes: &[u8], id: u8) -> usize {
    let mut at = KDBX_PREAMBLE_BYTES;
    loop {
        let len_bytes = bytes[at + 1..at + KDBX4_FIELD_PREFIX_BYTES]
            .try_into()
            .expect("4 bytes");
        let value_at = at + KDBX4_FIELD_PREFIX_BYTES;
        if bytes[at] == id {
            return value_at;
        }
        at = value_at + u32::from_le_bytes(len_bytes) as usize;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn undecodable_kdf_parameters_are_unreadable_under_any_password() {
    // KDF parameters that don't decode are header damage found before any key
    // is tried, so the verdict is the same whatever the credential.
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "vault.kdbx");
    create(&path, "Vault").await;
    let expected = root_uuid(&path, "pw");
    let mut bytes = std::fs::read(&path).expect("read vault");
    let major =
        kdbx4_field_value_at(&bytes, KDBX4_KDF_PARAMETERS_FIELD) + VAR_DICTIONARY_MAJOR_VERSION_AT;
    bytes[major] = !bytes[major];
    std::fs::write(&path, bytes).expect("write damaged copy");

    for password in ["pw", "wrong"] {
        let verdict = verify_vault_identity(
            path.clone(),
            password.to_owned(),
            None,
            expected.clone(),
            None,
        );
        assert!(
            matches!(verdict, Ok(VaultIdentityVerdict::Unreadable)),
            "password {password:?}: {verdict:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn header_failing_its_hash_is_unreadable_under_any_password() {
    // A KDBX4 header that still parses but fails its SHA-256 hash is damage
    // found without the key (the hash is unkeyed and checked before the KDF),
    // so the verdict is the same whatever the credential.
    let dir = TempDir::new().expect("tempdir");
    let path = fresh_path(&dir, "vault.kdbx");
    create(&path, "Vault").await;
    let expected = root_uuid(&path, "pw");
    let mut bytes = std::fs::read(&path).expect("read vault");
    let seed = kdbx4_field_value_at(&bytes, KDBX4_MASTER_SEED_FIELD);
    bytes[seed] = !bytes[seed];
    std::fs::write(&path, bytes).expect("write damaged copy");

    for password in ["pw", "wrong"] {
        let verdict = verify_vault_identity(
            path.clone(),
            password.to_owned(),
            None,
            expected.clone(),
            None,
        );
        assert!(
            matches!(verdict, Ok(VaultIdentityVerdict::Unreadable)),
            "password {password:?}: {verdict:?}"
        );
    }
}

/// A KeePassXC-written KDBX3 vault (AES-256-CBC outer cipher) from
/// `keepass-core`'s public fixture corpus, with its public test password.
const KDBX3_FIXTURE: &str = "keepassxc/kdbx3-basic.kdbx";
const KDBX3_FIXTURE_PASSWORD: &str = "tëst pässwörd 🔑/\\";
/// The AES-CBC block size: a KDBX3 payload is a whole number of these.
const AES_BLOCK_BYTES: usize = 16;
/// Bytes the KDBX3 header takes before its ciphertext starts in the fixture,
/// so truncation never cuts into the header.
const KDBX3_FIXTURE_HEADER_BYTES: usize = 222;

#[test]
fn kdbx3_payload_damage_is_undecryptable_not_unreadable() {
    // KDBX3 has no keyed header check: the key is proven only by decrypting
    // the payload. A verdict that tells padding failure (a key refusal) from
    // valid padding over a broken block stream (damage) is a CBC padding
    // oracle, so under the right password every payload failure must read as
    // a refusal. Covered: every byte of the last two ciphertext blocks
    // flipped, every value of the last byte of the second-to-last block (the
    // byte that sets the padding), and every whole-block truncation.
    let dir = TempDir::new().expect("tempdir");
    let fixture = common::fixture(KDBX3_FIXTURE);
    let intact = std::fs::read(&fixture).expect("read KDBX3 fixture");
    let expected = root_uuid(&fixture, KDBX3_FIXTURE_PASSWORD);
    let len = intact.len();

    let mut damaged: Vec<(String, Vec<u8>)> = Vec::new();
    for at in len - 2 * AES_BLOCK_BYTES..len {
        let mut bytes = intact.clone();
        bytes[at] = !bytes[at];
        damaged.push((format!("byte {at} flipped"), bytes));
    }
    let padding_byte = len - AES_BLOCK_BYTES - 1;
    for value in (0..=u8::MAX).filter(|v| *v != intact[padding_byte]) {
        let mut bytes = intact.clone();
        bytes[padding_byte] = value;
        damaged.push((format!("byte {padding_byte} set to {value:#04x}"), bytes));
    }
    let payload_blocks = (len - KDBX3_FIXTURE_HEADER_BYTES) / AES_BLOCK_BYTES;
    for blocks in 1..=payload_blocks {
        let bytes = intact[..len - blocks * AES_BLOCK_BYTES].to_vec();
        damaged.push((format!("{blocks} blocks truncated"), bytes));
    }

    let path = fresh_path(&dir, "damaged.kdbx");
    let wrong: Vec<String> = damaged
        .into_iter()
        .filter_map(|(name, bytes)| {
            std::fs::write(&path, bytes).expect("write damaged copy");
            let verdict = verify_vault_identity(
                path.clone(),
                KDBX3_FIXTURE_PASSWORD.to_owned(),
                None,
                expected.clone(),
                None,
            )
            .expect("verify");
            (verdict != VaultIdentityVerdict::Undecryptable).then(|| format!("{name}: {verdict:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "damage not reported as a key refusal:\n{}",
        wrong.join("\n")
    );
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
        None,
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
        None,
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
    let without = verify_vault_identity(path.clone(), "pw".to_owned(), None, any.clone(), None)
        .expect("verify");
    assert_eq!(without, VaultIdentityVerdict::Undecryptable);

    // Right password, WRONG keyfile → Undecryptable.
    let wrong_keyfile = generate_keyfile().expect("mint second keyfile");
    let wrong = verify_vault_identity(path, "pw".to_owned(), Some(wrong_keyfile), any, None)
        .expect("verify");
    assert_eq!(wrong, VaultIdentityVerdict::Undecryptable);
}
