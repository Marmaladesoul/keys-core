//! Integration tests for [`Engine::open`] / [`Engine::close`].

use keys_engine::{DbKey, Engine, EngineError, KeyProvider, KeyProviderError};

#[derive(Debug)]
struct FixedKey([u8; 32]);

impl KeyProvider for FixedKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.0))
    }
}

#[derive(Debug)]
struct FailingKey(String);

impl KeyProvider for FailingKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Err(KeyProviderError::KeyUnavailable(self.0.clone()))
    }
}

#[test]
fn open_creates_new_db_file_and_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let key = FixedKey([0x42; 32]);

    let engine = Engine::open(&path, &key).expect("open new");
    engine.close().expect("close");
    assert!(path.exists(), "db file should be created");

    // Reopen with the same key. Write something, prove round-trip.
    let engine = Engine::open(&path, &key).expect("reopen with same key");
    // We can't access the connection directly from outside the crate
    // (and shouldn't — 1.5 lands the migration runner). The sanity
    // query in `open` already proves we decrypted the header. Use
    // another sanity round-trip via close + reopen.
    engine.close().expect("close");

    let engine = Engine::open(&path, &key).expect("reopen again");
    engine.close().expect("close");
}

#[test]
fn open_under_wrong_key_returns_wrong_key_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");

    let key_a = FixedKey([0xaa; 32]);
    Engine::open(&path, &key_a)
        .expect("create with key A")
        .close()
        .expect("close A");

    let key_b = FixedKey([0xbb; 32]);
    let err = Engine::open(&path, &key_b).expect_err("wrong key must fail");
    assert!(
        matches!(err, EngineError::WrongKey),
        "expected WrongKey, got {err:?}",
    );
}

#[test]
fn open_creates_new_db_file_when_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nested-but-not-too-nested.db");
    assert!(!path.exists());

    let engine = Engine::open(&path, &FixedKey([0x11; 32])).expect("open creates file");
    engine.close().expect("close");
    assert!(path.exists());
}

#[test]
fn key_provider_error_is_propagated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    let provider = FailingKey("keychain locked".into());

    let err = Engine::open(&path, &provider).expect_err("provider failure must surface");
    match err {
        EngineError::KeyProvider(KeyProviderError::KeyUnavailable(msg)) => {
            assert_eq!(msg, "keychain locked");
        }
        other => panic!("expected KeyProvider error, got {other:?}"),
    }
    assert!(
        !path.exists(),
        "db file must not be created when provider fails",
    );
}
